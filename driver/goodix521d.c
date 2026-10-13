/*
 * Goodix 27c6:521d (GF5298) press sensor, matched on the host with SIGFM.
 *
 * The sensor only delivers raw 64x80 12-bit images over a TLS-PSK link.
 * The PSK is the one Windows sealed into the sensor; it is read from a
 * root-only file and checked against the hash the sensor reports, so the
 * driver never writes keys or firmware. The sensor config and capture DACs
 * come from the sensor's factory calibration (OTP), copied from the Windows
 * driver's goodix.dat at install time.
 *
 * No resets of any kind are sent: an MCU soft reset once left this chip
 * unresponsive until the laptop was fully powered down. A stale reply left
 * by an earlier session is drained instead.
 *
 * Images: at the operating DAC (0xb8) the empty sensor saturates, so the
 * background cannot come from an empty frame. It is the per-pixel median of
 * all finger frames seen during enrollment, stored in the print and
 * subtracted from every later frame.
 *
 * The USB work is blocking and runs in a GTask thread, one finger press per
 * task; all libfprint calls stay on the main context.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define FP_COMPONENT "goodix521d"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "drivers_api.h"
#include "goodix521d_config.h"
#include "sigfm.h"

#define EP_IN (0x83)
#define EP_OUT (0x01)
#define USB_TIMEOUT 2000
#define USB_CHUNK 0x40
#define USB_READ_MAX 0x10000

#define FLAGS_PROTOCOL 0xa0
#define FLAGS_TLS 0xb0
#define FLAGS_TLS_DATA 0xb2

#define CMD_NOP 0x00
#define CMD_MCU_GET_IMAGE 0x20
#define CMD_WRITE_SENSOR_REGISTER 0x80
#define CMD_UPLOAD_CONFIG_MCU 0x90
#define CMD_FIRMWARE_VERSION 0xa8
#define CMD_ACK 0xb0
#define CMD_SET_DRV_STATE 0xc4
#define CMD_REQUEST_TLS_CONNECTION 0xd0
#define CMD_PRESET_PSK_READ 0xe4

#define FIRMWARE_VERSION "GFUSB_GM168SEC_APP_10019"
#define PSK_FLAGS 0xbb020001
#define PSK_LEN 32
#define DATA_DIR "/etc/goodix-521d" /* psk (hex), otp.bin */

#define IMAGE_PLAIN_LEN 7684 /* 5120 12-bit pixels + 4 trailing bytes */
#define WARMUP_FRAMES 6

/* Frame mean (12-bit): the empty sensor sits near 3930 at DAC 0xb8, a
 * finger pulls it to ~2000-2400. */
#define FINGER_LEVEL 2400
#define LIFTED_LEVEL 3700

#define POLL_MS 60
#define FRAME_GAP_MS 150
#define PRESS_FRAMES 4    /* frames kept per press */
#define PRESS_MAX_MS 2500 /* stop collecting after this long */
#define TEMPLATE_FRAMES 3 /* of those, frames stored per enroll stage */
#define ENROLL_STAGES 32

/* Geometrically consistent match pairs needed to accept. Genuine presses
 * that overlap the enrollment score from ~15 into the hundreds; another
 * finger scored 0 in every test. */
#define MATCH_THRESHOLD 12

#define PRINT_VERSION 1
#define PRINT_FORMAT "(u@aq@aay)"
#define PRINT_TYPE "(uaqaay)"

struct _FpiDeviceGoodix521d
{
  FpDevice   parent;

  guint8     psk[PSK_LEN];
  guint8     config[GOODIX521D_CONFIG_LEN];
  guint8     image_request[10]; /* mode 0x45 0x03, four DACs (LE16) */
  SSL_CTX   *ssl_ctx;
  SSL       *ssl;
  BIO       *rbio;
  BIO       *wbio;

  /* enrollment */
  GPtrArray *enroll_all; /* every finger frame: background estimate */
  GPtrArray *enroll_sel; /* frames kept for the template */
  gint       enroll_stage;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix521d, fpi_device_goodix521d, FPI,
                      DEVICE_GOODIX521D, FpDevice)
G_DEFINE_TYPE (FpiDeviceGoodix521d, fpi_device_goodix521d, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
  { .vid = 0x27c6, .pid = 0x521d },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

/* ---- USB transport (worker thread) ---------------------------------- */

static gboolean
usb_write (FpiDeviceGoodix521d *self, const guint8 *data, gsize len,
           GError **error)
{
  GUsbDevice *usb = fpi_device_get_usb_device (FP_DEVICE (self));
  gsize padded = (len + USB_CHUNK - 1) / USB_CHUNK * USB_CHUNK;
  g_autofree guint8 *buf = g_malloc0 (padded);

  memcpy (buf, data, len);
  for (gsize i = 0; i < padded; i += USB_CHUNK)
    {
      gsize actual = 0;

      if (!g_usb_device_bulk_transfer (usb, EP_OUT, buf + i, USB_CHUNK,
                                       &actual, USB_TIMEOUT, NULL, error))
        return FALSE;
    }
  return TRUE;
}

static gboolean
usb_read (FpiDeviceGoodix521d *self, guint8 *buf, gsize len, gsize *actual,
          guint timeout, GError **error)
{
  GUsbDevice *usb = fpi_device_get_usb_device (FP_DEVICE (self));

  return g_usb_device_bulk_transfer (usb, EP_IN, buf, len, actual, timeout,
                                     NULL, error);
}

/* Throw away replies left queued by a previous session. */
static void
usb_drain (FpiDeviceGoodix521d *self)
{
  g_autofree guint8 *buf = g_malloc (USB_READ_MAX);

  for (int i = 0; i < 50; i++)
    {
      gsize actual;

      if (!usb_read (self, buf, USB_READ_MAX, &actual, 100, NULL))
        return;
    }
}

/* ---- Message framing ------------------------------------------------ */

static GByteArray *
encode_pack (guint8 flags, const guint8 *payload, gsize len)
{
  GByteArray *out = g_byte_array_sized_new (len + 4);
  guint8 head[4] = { flags, len & 0xff, (len >> 8) & 0xff, 0 };

  head[3] = (head[0] + head[1] + head[2]) & 0xff;
  g_byte_array_append (out, head, 4);
  g_byte_array_append (out, payload, len);
  return out;
}

static GByteArray *
encode_protocol (guint8 cmd, const guint8 *payload, gsize len,
                 gboolean checksum)
{
  GByteArray *out = g_byte_array_sized_new (len + 4);
  guint8 head[3] = { cmd, (len + 1) & 0xff, ((len + 1) >> 8) & 0xff };
  guint8 sum = 0, tail;

  g_byte_array_append (out, head, 3);
  g_byte_array_append (out, payload, len);
  for (guint i = 0; i < out->len; i++)
    sum += out->data[i];
  tail = checksum ? (guint8) (0xaa - sum) : 0x88;
  g_byte_array_append (out, &tail, 1);
  return out;
}

static gboolean
send_pack (FpiDeviceGoodix521d *self, guint8 flags, const guint8 *payload,
           gsize len, GError **error)
{
  g_autoptr(GByteArray) pack = encode_pack (flags, payload, len);

  return usb_write (self, pack->data, pack->len, error);
}

/* Read one message pack and return its payload. */
static GByteArray *
read_pack (FpiDeviceGoodix521d *self, guint8 want_flags, GError **error)
{
  g_autofree guint8 *buf = g_malloc (USB_READ_MAX);
  gsize have = 0, actual, len;

  if (!usb_read (self, buf, USB_READ_MAX, &have, USB_TIMEOUT, error))
    return NULL;
  if (have < 4 || ((buf[0] + buf[1] + buf[2]) & 0xff) != buf[3])
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Invalid message pack");
      return NULL;
    }
  len = buf[1] | (buf[2] << 8);
  while (have < len + 4)
    {
      if (have >= USB_READ_MAX)
        {
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                       "Message pack too long");
          return NULL;
        }
      if (!usb_read (self, buf + have, USB_READ_MAX - have, &actual,
                     USB_TIMEOUT, error))
        return NULL;
      have += actual;
    }
  if (buf[0] != want_flags)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected message flags 0x%02x", buf[0]);
      return NULL;
    }
  return g_byte_array_new_take (g_memdup2 (buf + 4, len), len);
}

static GByteArray *
read_protocol (FpiDeviceGoodix521d *self, guint8 want_cmd, GError **error)
{
  g_autoptr(GByteArray) pack = read_pack (self, FLAGS_PROTOCOL, error);
  guint8 sum = 0;
  gsize len;

  if (!pack)
    return NULL;
  if (pack->len < 4)
    goto invalid;
  len = pack->data[1] | (pack->data[2] << 8);
  if (pack->len < len + 3 || len < 1)
    goto invalid;
  for (gsize i = 0; i < len + 2; i++)
    sum += pack->data[i];
  if (pack->data[0] != want_cmd || pack->data[len + 2] != (guint8) (0xaa - sum))
    goto invalid;
  return g_byte_array_new_take (g_memdup2 (pack->data + 3, len - 1), len - 1);

invalid:
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "Invalid message protocol (wanted command 0x%02x)", want_cmd);
  return NULL;
}

/* Send a command and wait for its ACK. */
static gboolean
command (FpiDeviceGoodix521d *self, guint8 cmd, const guint8 *payload,
         gsize len, GError **error)
{
  g_autoptr(GByteArray) msg = encode_protocol (cmd, payload, len, TRUE);
  g_autoptr(GByteArray) ack = NULL;

  if (!send_pack (self, FLAGS_PROTOCOL, msg->data, msg->len, error))
    return FALSE;
  ack = read_protocol (self, CMD_ACK, error);
  if (!ack)
    return FALSE;
  if (ack->len < 2 || ack->data[0] != cmd || !(ack->data[1] & 0x1))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Invalid ACK for command 0x%02x", cmd);
      return FALSE;
    }
  return TRUE;
}

/* ---- Commands ------------------------------------------------------- */

static gboolean
cmd_nop (FpiDeviceGoodix521d *self, GError **error)
{
  const guint8 payload[4] = { 0 };
  g_autoptr(GByteArray) msg = encode_protocol (CMD_NOP, payload, 4, FALSE);
  g_autofree guint8 *buf = g_malloc (USB_READ_MAX);
  g_autoptr(GError) local = NULL;
  gsize actual;

  if (!send_pack (self, FLAGS_PROTOCOL, msg->data, msg->len, error))
    return FALSE;
  /* Usually there is no reply at all; a reply must be its ACK. */
  if (!usb_read (self, buf, USB_READ_MAX, &actual, 100, &local))
    {
      if (g_error_matches (local, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_TIMED_OUT))
        return TRUE;
      g_propagate_error (error, g_steal_pointer (&local));
      return FALSE;
    }
  if (actual >= 9 && buf[0] == FLAGS_PROTOCOL && buf[4] == CMD_ACK &&
      buf[7] == CMD_NOP)
    return TRUE;
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "Unexpected reply to NOP");
  return FALSE;
}

static gchar *
cmd_firmware_version (FpiDeviceGoodix521d *self, GError **error)
{
  const guint8 payload[2] = { 0 };
  g_autoptr(GByteArray) reply = NULL;

  if (!command (self, CMD_FIRMWARE_VERSION, payload, 2, error))
    return NULL;
  reply = read_protocol (self, CMD_FIRMWARE_VERSION, error);
  if (!reply)
    return NULL;
  return g_strndup ((const gchar *) reply->data, reply->len);
}

/* The sensor reports the SHA-256 of its PSK, never the key. */
static gboolean
cmd_preset_psk_hash (FpiDeviceGoodix521d *self, guint8 hash[32],
                     GError **error)
{
  guint8 payload[16] = { 0 };
  g_autoptr(GByteArray) reply = NULL;
  guint32 flags, len;

  payload[0] = PSK_LEN; /* length (LE32), offset 0 (LE32) */
  payload[8] = PSK_FLAGS & 0xff;
  payload[9] = (PSK_FLAGS >> 8) & 0xff;
  payload[10] = (PSK_FLAGS >> 16) & 0xff;
  payload[11] = (PSK_FLAGS >> 24) & 0xff;
  if (!command (self, CMD_PRESET_PSK_READ, payload, sizeof payload, error))
    return FALSE;
  reply = read_protocol (self, CMD_PRESET_PSK_READ, error);
  if (!reply)
    return FALSE;
  if (reply->len < 9 || reply->data[0] != 0x00)
    goto invalid;
  flags = GUINT32_FROM_LE (*(guint32 *) (reply->data + 1));
  len = GUINT32_FROM_LE (*(guint32 *) (reply->data + 5));
  if (flags != PSK_FLAGS || len != 32 || reply->len < 9 + len)
    goto invalid;
  memcpy (hash, reply->data + 9, 32);
  return TRUE;

invalid:
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "Could not read the sensor's PSK hash");
  return FALSE;
}

static gboolean
cmd_upload_config (FpiDeviceGoodix521d *self, GError **error)
{
  g_autoptr(GByteArray) reply = NULL;

  if (!command (self, CMD_UPLOAD_CONFIG_MCU, self->config,
                sizeof self->config, error))
    return FALSE;
  reply = read_protocol (self, CMD_UPLOAD_CONFIG_MCU, error);
  if (!reply)
    return FALSE;
  if (reply->len < 1 || reply->data[0] != 0x01)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Sensor rejected the config");
      return FALSE;
    }
  return TRUE;
}

static gboolean
cmd_write_register (FpiDeviceGoodix521d *self, guint16 address, guint8 v0,
                    guint8 v1, GError **error)
{
  const guint8 payload[5] = { 0x00, address & 0xff, address >> 8, v0, v1 };

  return command (self, CMD_WRITE_SENSOR_REGISTER, payload, 5, error);
}

/* ---- TLS (sensor is the client) ------------------------------------- */

static unsigned int
psk_server_cb (SSL *ssl, const char *identity, unsigned char *psk,
               unsigned int max_psk_len)
{
  FpiDeviceGoodix521d *self = SSL_get_app_data (ssl);

  if (max_psk_len < PSK_LEN)
    return 0;
  memcpy (psk, self->psk, PSK_LEN);
  return PSK_LEN;
}

static void
tls_free (FpiDeviceGoodix521d *self)
{
  g_clear_pointer (&self->ssl, SSL_free); /* frees both BIOs */
  self->rbio = self->wbio = NULL;
  g_clear_pointer (&self->ssl_ctx, SSL_CTX_free);
}

static gboolean
tls_error (GError **error, const gchar *what)
{
  gchar buf[256] = "";

  ERR_error_string_n (ERR_get_error (), buf, sizeof buf);
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "TLS %s failed: %s", what, buf);
  return FALSE;
}

/* Feed bytes from the sensor, advance the handshake, collect output. */
static gboolean
tls_step (FpiDeviceGoodix521d *self, const guint8 *in, gsize len,
          GByteArray *out, gboolean *done, GError **error)
{
  guint8 buf[4096];
  int r;

  if (len)
    BIO_write (self->rbio, in, len);
  r = SSL_do_handshake (self->ssl);
  *done = r == 1;
  if (r != 1 && SSL_get_error (self->ssl, r) != SSL_ERROR_WANT_READ)
    return tls_error (error, "handshake");
  while ((r = BIO_read (self->wbio, buf, sizeof buf)) > 0)
    g_byte_array_append (out, buf, r);
  return TRUE;
}

static gboolean
tls_connect (FpiDeviceGoodix521d *self, GError **error)
{
  const guint8 payload[2] = { 0 };
  g_autoptr(GByteArray) out = g_byte_array_new ();
  gboolean done = FALSE;

  self->ssl_ctx = SSL_CTX_new (TLS_server_method ());
  if (!self->ssl_ctx)
    return tls_error (error, "setup");
  SSL_CTX_set_min_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  if (!SSL_CTX_set_cipher_list (self->ssl_ctx, "PSK:@SECLEVEL=0"))
    return tls_error (error, "setup");
  SSL_CTX_set_psk_server_callback (self->ssl_ctx, psk_server_cb);

  self->ssl = SSL_new (self->ssl_ctx);
  self->rbio = BIO_new (BIO_s_mem ());
  self->wbio = BIO_new (BIO_s_mem ());
  SSL_set_bio (self->ssl, self->rbio, self->wbio);
  SSL_set_app_data (self->ssl, self);
  SSL_set_accept_state (self->ssl);

  /* client hello */
  if (!command (self, CMD_REQUEST_TLS_CONNECTION, payload, 2, error))
    return FALSE;
  {
    g_autoptr(GByteArray) hello = read_pack (self, FLAGS_TLS, error);

    if (!hello || !tls_step (self, hello->data, hello->len, out, &done, error))
      return FALSE;
  }
  if (!send_pack (self, FLAGS_TLS, out->data, out->len, error))
    return FALSE;
  g_byte_array_set_size (out, 0);

  /* client key exchange, change cipher spec, finished */
  for (int i = 0; i < 3; i++)
    {
      g_autoptr(GByteArray) msg = read_pack (self, FLAGS_TLS, error);

      if (!msg || !tls_step (self, msg->data, msg->len, out, &done, error))
        return FALSE;
    }
  if (!done)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "TLS handshake did not complete");
      return FALSE;
    }
  if (!send_pack (self, FLAGS_TLS, out->data, out->len, error))
    return FALSE;
  g_usleep (10 * 1000);

  fp_dbg ("TLS established: %s", SSL_get_cipher_name (self->ssl));
  return TRUE;
}

/* ---- Imaging -------------------------------------------------------- */

static gboolean
grab (FpiDeviceGoodix521d *self, guint16 *frame, GError **error)
{
  g_autoptr(GByteArray) msg = NULL;
  g_autofree guint8 *plain = g_malloc (IMAGE_PLAIN_LEN);
  gsize have = 0;

  if (!cmd_write_register (self, 0x022c, 0x05, 0x03, error))
    return FALSE;
  if (!command (self, CMD_MCU_GET_IMAGE, self->image_request,
                sizeof self->image_request, error))
    return FALSE;
  msg = read_pack (self, FLAGS_TLS_DATA, error);
  if (!msg)
    return FALSE;
  if (msg->len <= 9)
    goto invalid;

  /* The TLS record follows a 9-byte header. */
  BIO_write (self->rbio, msg->data + 9, msg->len - 9);
  while (have < IMAGE_PLAIN_LEN)
    {
      int r = SSL_read (self->ssl, plain + have, IMAGE_PLAIN_LEN - have);

      if (r <= 0)
        break;
      have += r;
    }
  if (!cmd_write_register (self, 0x022c, 0x0a, 0x02, error))
    return FALSE;
  if (have != IMAGE_PLAIN_LEN)
    goto invalid;

  /* 4 pixels per 6 bytes */
  for (int i = 0, p = 0; p < SIGFM_PIXELS; i += 6)
    {
      const guint8 *c = plain + i;

      frame[p++] = ((c[0] & 0xf) << 8) + c[1];
      frame[p++] = (c[3] << 4) + (c[0] >> 4);
      frame[p++] = ((c[5] & 0xf) << 8) + c[2];
      frame[p++] = (c[4] << 4) + (c[5] >> 4);
    }
  return TRUE;

invalid:
  ERR_clear_error ();
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "Unexpected image size %" G_GSIZE_FORMAT, have);
  return FALSE;
}

static guint
frame_mean (const guint16 *frame)
{
  guint64 sum = 0;

  for (int i = 0; i < SIGFM_PIXELS; i++)
    sum += frame[i];
  return sum / SIGFM_PIXELS;
}

/* ---- Open / close --------------------------------------------------- */

static gboolean
load_psk (FpiDeviceGoodix521d *self, const gchar *dir, GError **error)
{
  g_autofree gchar *path = g_build_filename (dir, "psk", NULL);
  g_autofree gchar *text = NULL;
  g_autofree guint8 *key = NULL;
  gsize len;

  if (!g_file_get_contents (path, &text, NULL, error))
    return FALSE;
  g_strstrip (text);
  if (strlen (text) != PSK_LEN * 2)
    goto invalid;
  key = g_malloc (PSK_LEN);
  for (len = 0; len < PSK_LEN; len++)
    {
      gint hi = g_ascii_xdigit_value (text[2 * len]);
      gint lo = g_ascii_xdigit_value (text[2 * len + 1]);

      if (hi < 0 || lo < 0)
        goto invalid;
      key[len] = hi << 4 | lo;
    }
  memcpy (self->psk, key, PSK_LEN);
  memset (text, 0, strlen (text));
  memset (key, 0, PSK_LEN);
  return TRUE;

invalid:
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
               "%s must hold the 32-byte PSK as hex", path);
  return FALSE;
}

static gboolean
load_otp (FpiDeviceGoodix521d *self, const gchar *dir, GError **error)
{
  g_autofree gchar *path = g_build_filename (dir, "otp.bin", NULL);
  g_autofree gchar *otp = NULL;
  guint16 dacs[4];
  gsize len;

  if (!g_file_get_contents (path, &otp, &len, error))
    return FALSE;
  if (len != GOODIX521D_OTP_LEN ||
      goodix521d_build_config ((const guint8 *) otp, self->config, dacs) < 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "%s is not this sensor's OTP calibration", path);
      return FALSE;
    }
  self->image_request[0] = 0x45;
  self->image_request[1] = 0x03;
  for (int i = 0; i < 4; i++)
    {
      self->image_request[2 + 2 * i] = dacs[i] & 0xff;
      self->image_request[3 + 2 * i] = dacs[i] >> 8;
    }
  fp_dbg ("DACs %x %x %x %x", dacs[0], dacs[1], dacs[2], dacs[3]);
  return TRUE;
}

static gboolean
sensor_init (FpiDeviceGoodix521d *self, GError **error)
{
  g_autofree gchar *firmware = NULL;
  g_autoptr(GChecksum) sha = g_checksum_new (G_CHECKSUM_SHA256);
  guint8 hash[32], want[32];
  gsize hash_len = sizeof want;
  guint16 frame[SIGFM_PIXELS];

  const gchar *dir = g_getenv ("GOODIX_521D_DIR");

  if (!dir)
    dir = DATA_DIR;
  if (!load_psk (self, dir, error) || !load_otp (self, dir, error))
    return FALSE;

  /* A reply left over from an earlier session desyncs the first reads;
   * drain and retry until the link answers cleanly. */
  for (int attempt = 0; attempt < 6 && !firmware; attempt++)
    {
      g_autoptr(GError) local = NULL;

      usb_drain (self);
      if (cmd_nop (self, &local))
        firmware = cmd_firmware_version (self, &local);
      if (!firmware)
        {
          fp_dbg ("link resync attempt %d: %s", attempt, local->message);
          g_usleep (300 * 1000);
        }
    }
  if (!firmware)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Sensor does not answer");
      return FALSE;
    }
  fp_dbg ("firmware %s", firmware);
  if (g_strcmp0 (firmware, FIRMWARE_VERSION) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED,
                   "Unsupported firmware %s", firmware);
      return FALSE;
    }

  if (!cmd_preset_psk_hash (self, hash, error))
    return FALSE;
  g_checksum_update (sha, self->psk, PSK_LEN);
  g_checksum_get_digest (sha, want, &hash_len);
  if (memcmp (hash, want, sizeof want) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "The PSK does not match the key in the sensor");
      return FALSE;
    }

  if (!tls_connect (self, error))
    return FALSE;
  if (!cmd_upload_config (self, error))
    return FALSE;
  {
    const guint8 drv_state[2] = { 0x01, 0x00 };

    if (!command (self, CMD_SET_DRV_STATE, drv_state, 2, error))
      return FALSE;
  }

  /* The first frames after the config can saturate. */
  for (int i = 0; i < WARMUP_FRAMES; i++)
    if (!grab (self, frame, error))
      return FALSE;
  fp_dbg ("sensor ready, empty frame mean %u", frame_mean (frame));
  return TRUE;
}

static void
open_thread (GTask *task, gpointer source, gpointer data,
             GCancellable *cancellable)
{
  FpiDeviceGoodix521d *self = source;
  GUsbDevice *usb = fpi_device_get_usb_device (FP_DEVICE (self));
  GError *error = NULL;

  if (!g_usb_device_claim_interface (usb, 0, 0, &error))
    {
      g_task_return_error (task, error);
      return;
    }
  if (!sensor_init (self, &error))
    {
      tls_free (self);
      g_usb_device_release_interface (usb, 0, 0, NULL);
      g_task_return_error (task, error);
      return;
    }
  g_task_return_boolean (task, TRUE);
}

static void
open_done (GObject *source, GAsyncResult *res, gpointer data)
{
  GError *error = NULL;

  g_task_propagate_boolean (G_TASK (res), &error);
  fpi_device_open_complete (FP_DEVICE (source), error);
}

static void
dev_open (FpDevice *device)
{
  g_autoptr(GTask) task = g_task_new (device, NULL, open_done, NULL);

  g_task_run_in_thread (task, open_thread);
}

static void
dev_close (FpDevice *device)
{
  FpiDeviceGoodix521d *self = FPI_DEVICE_GOODIX521D (device);
  GError *error = NULL;

  tls_free (self);
  memset (self->psk, 0, PSK_LEN);
  g_usb_device_release_interface (fpi_device_get_usb_device (device), 0, 0,
                                  &error);
  fpi_device_close_complete (device, error);
}

/* ---- One finger press (worker thread) ------------------------------- */

typedef struct
{
  gboolean   need_lift;
  GPtrArray *frames;  /* guint16[SIGFM_PIXELS] */
  GPtrArray *gallery; /* GVariant prints to match, or NULL */
  gint       match;   /* index into gallery, -1 if none */
  gint       score;
  gboolean   probe_ok;
} PressData;

static void
press_data_free (PressData *d)
{
  g_clear_pointer (&d->frames, g_ptr_array_unref);
  g_clear_pointer (&d->gallery, g_ptr_array_unref);
  g_free (d);
}

static gboolean
press_cancelled (GCancellable *cancellable, GError **error)
{
  return g_cancellable_set_error_if_cancelled (cancellable, error);
}

/* Cancellation is only honoured between grabs, so a request is never cut
 * in half and the link stays in step. */
static gboolean
capture_press (FpiDeviceGoodix521d *self, PressData *d,
               GCancellable *cancellable, GError **error)
{
  g_autofree guint16 *frame = g_new (guint16, SIGFM_PIXELS);
  gint64 last = 0, start;

  while (d->need_lift)
    {
      if (press_cancelled (cancellable, error) || !grab (self, frame, error))
        return FALSE;
      if (frame_mean (frame) > LIFTED_LEVEL)
        break;
      g_usleep (POLL_MS * 1000);
    }

  for (;;)
    {
      if (press_cancelled (cancellable, error) || !grab (self, frame, error))
        return FALSE;
      if (frame_mean (frame) < FINGER_LEVEL)
        break;
      g_usleep (POLL_MS * 1000);
    }

  /* Finger down: keep frames while it settles. */
  start = g_get_monotonic_time ();
  for (;;)
    {
      guint mean = frame_mean (frame);

      if (mean > LIFTED_LEVEL ||
          g_get_monotonic_time () - start > PRESS_MAX_MS * 1000)
        break;
      if (mean < FINGER_LEVEL && g_get_monotonic_time () - last >= FRAME_GAP_MS * 1000)
        {
          g_ptr_array_add (d->frames, g_memdup2 (frame, SIGFM_PIXELS * 2));
          last = g_get_monotonic_time ();
          if (d->frames->len >= PRESS_FRAMES)
            break;
        }
      if (press_cancelled (cancellable, error))
        return FALSE;
      g_usleep (POLL_MS * 1000);
      if (!grab (self, frame, error))
        return FALSE;
    }
  fp_dbg ("press captured, %u frames", d->frames->len);
  return TRUE;
}

static gboolean
print_unpack (GVariant *data, const guint16 **background,
              GVariant **images)
{
  g_autoptr(GVariant) bg = NULL;
  gsize n = 0;
  guint32 version;

  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE (PRINT_TYPE)))
    return FALSE;
  g_variant_get (data, PRINT_FORMAT, &version, &bg, images);
  *background = g_variant_get_fixed_array (bg, &n, sizeof (guint16));
  if (version != PRINT_VERSION || n != SIGFM_PIXELS)
    {
      g_clear_pointer (images, g_variant_unref);
      return FALSE;
    }
  return TRUE; /* background stays valid: data holds a reference */
}

/* Best score of the press against one print. */
static gint
match_print (GVariant *data, PressData *d)
{
  const guint16 *background;
  g_autoptr(GVariant) images = NULL;
  g_autoptr(GPtrArray) probe = g_ptr_array_new_with_free_func ((GDestroyNotify) sigfm_free);
  guint8 img[SIGFM_PIXELS];
  gint best = 0;

  if (!print_unpack (data, &background, &images))
    {
      fp_warn ("ignoring a print in an unknown format");
      return 0;
    }

  for (guint i = 0; i < d->frames->len; i++)
    {
      SigfmFeatures *f;

      sigfm_prepare (background, g_ptr_array_index (d->frames, i), img);
      f = sigfm_extract (img);
      if (sigfm_keypoints (f) > 0)
        d->probe_ok = TRUE;
      g_ptr_array_add (probe, f);
    }

  for (gsize i = 0; i < g_variant_n_children (images) && best < MATCH_THRESHOLD; i++)
    {
      g_autoptr(GVariant) child = g_variant_get_child_value (images, i);
      gsize n;
      const guint8 *t = g_variant_get_fixed_array (child, &n, 1);
      SigfmFeatures *tf;

      if (n != SIGFM_PIXELS)
        continue;
      tf = sigfm_extract (t);
      for (guint j = 0; j < probe->len; j++)
        best = MAX (best, sigfm_score (g_ptr_array_index (probe, j), tf, 1000));
      sigfm_free (tf);
    }
  return best;
}

static void
press_thread (GTask *task, gpointer source, gpointer data,
              GCancellable *cancellable)
{
  FpiDeviceGoodix521d *self = source;
  PressData *d = data;
  GError *error = NULL;

  if (!capture_press (self, d, cancellable, &error))
    {
      g_task_return_error (task, error);
      return;
    }

  /* An empty gallery (fprintd's duplicate check before the first enroll)
   * is a plain "no match", not a bad press. */
  if (d->gallery && d->gallery->len == 0)
    d->probe_ok = TRUE;

  if (d->gallery)
    {
      for (guint i = 0; i < d->gallery->len; i++)
        {
          gint score = match_print (g_ptr_array_index (d->gallery, i), d);

          fp_info ("print %u: score %d (threshold %d)", i, score,
                   MATCH_THRESHOLD);
          if (score > d->score)
            d->score = score;
          if (score >= MATCH_THRESHOLD)
            {
              d->match = i;
              break;
            }
        }
    }
  g_task_return_boolean (task, TRUE);
}

static void
start_press (FpDevice *device, gboolean need_lift, GPtrArray *gallery,
             GAsyncReadyCallback done)
{
  g_autoptr(GTask) task = g_task_new (device, fpi_device_get_cancellable (device),
                                      done, NULL);
  PressData *d = g_new0 (PressData, 1);

  d->need_lift = need_lift;
  d->frames = g_ptr_array_new_with_free_func (g_free);
  d->gallery = gallery;
  d->match = -1;
  g_task_set_task_data (task, d, (GDestroyNotify) press_data_free);
  g_task_set_return_on_cancel (task, FALSE);

  fpi_device_report_finger_status_changes (device, FP_FINGER_STATUS_NEEDED,
                                           FP_FINGER_STATUS_NONE);
  g_task_run_in_thread (task, press_thread);
}

/* ---- Enroll --------------------------------------------------------- */

static void enroll_press_done (GObject *source, GAsyncResult *res,
                               gpointer user_data);

static void
enroll_clear (FpiDeviceGoodix521d *self)
{
  g_clear_pointer (&self->enroll_all, g_ptr_array_unref);
  g_clear_pointer (&self->enroll_sel, g_ptr_array_unref);
}

static void
enroll_finish (FpDevice *device)
{
  FpiDeviceGoodix521d *self = FPI_DEVICE_GOODIX521D (device);
  g_autofree guint16 *background = g_new (guint16, SIGFM_PIXELS);
  GVariantBuilder images;
  FpPrint *print = NULL;
  guint8 img[SIGFM_PIXELS];
  guint kept = 0;

  sigfm_median ((const uint16_t *const *) self->enroll_all->pdata,
                self->enroll_all->len, background);

  g_variant_builder_init (&images, G_VARIANT_TYPE ("aay"));
  for (guint i = 0; i < self->enroll_sel->len; i++)
    {
      SigfmFeatures *f;
      gboolean usable;

      sigfm_prepare (background, g_ptr_array_index (self->enroll_sel, i), img);
      f = sigfm_extract (img);
      usable = sigfm_keypoints (f) >= 5;
      sigfm_free (f);
      if (!usable)
        continue;
      g_variant_builder_add_value (&images,
                                   g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                              img, SIGFM_PIXELS, 1));
      kept++;
    }
  fp_info ("enrolled %u template images from %u frames", kept,
           self->enroll_all->len);
  enroll_clear (self);

  if (kept == 0)
    {
      g_variant_builder_clear (&images);
      fpi_device_enroll_complete (device, NULL,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "No usable fingerprint images"));
      return;
    }

  fpi_device_get_enroll_data (device, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, FALSE);
  g_object_set (print, "fpi-data",
                g_variant_new (PRINT_FORMAT, PRINT_VERSION,
                               g_variant_new_fixed_array (G_VARIANT_TYPE_UINT16,
                                                          background, SIGFM_PIXELS,
                                                          sizeof (guint16)),
                               g_variant_builder_end (&images)),
                NULL);
  fpi_device_enroll_complete (device, g_object_ref (print), NULL);
}

static void
enroll_press_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
  FpDevice *device = FP_DEVICE (source);
  FpiDeviceGoodix521d *self = FPI_DEVICE_GOODIX521D (device);
  PressData *d = g_task_get_task_data (G_TASK (res));
  GError *error = NULL;
  guint n;

  fpi_device_report_finger_status_changes (device, FP_FINGER_STATUS_NONE,
                                           FP_FINGER_STATUS_NEEDED);
  if (!g_task_propagate_boolean (G_TASK (res), &error))
    {
      enroll_clear (self);
      fpi_device_enroll_complete (device, NULL, error);
      return;
    }

  n = d->frames->len;
  for (guint i = 0; i < n; i++)
    g_ptr_array_add (self->enroll_all,
                     g_memdup2 (g_ptr_array_index (d->frames, i), SIGFM_PIXELS * 2));
  /* Up to TEMPLATE_FRAMES spread over the press. */
  for (guint k = 0; k < MIN (n, TEMPLATE_FRAMES); k++)
    {
      guint i = MIN (n, TEMPLATE_FRAMES) > 1 ? k * (n - 1) / (MIN (n, TEMPLATE_FRAMES) - 1) : 0;

      g_ptr_array_add (self->enroll_sel,
                       g_memdup2 (g_ptr_array_index (d->frames, i), SIGFM_PIXELS * 2));
    }

  self->enroll_stage++;
  fpi_device_enroll_progress (device, self->enroll_stage, NULL, NULL);
  if (self->enroll_stage < fp_device_get_nr_enroll_stages (device))
    start_press (device, TRUE, NULL, enroll_press_done);
  else
    enroll_finish (device);
}

static void
dev_enroll (FpDevice *device)
{
  FpiDeviceGoodix521d *self = FPI_DEVICE_GOODIX521D (device);

  enroll_clear (self);
  self->enroll_all = g_ptr_array_new_with_free_func (g_free);
  self->enroll_sel = g_ptr_array_new_with_free_func (g_free);
  self->enroll_stage = 0;
  start_press (device, TRUE, NULL, enroll_press_done);
}

/* ---- Verify / identify ---------------------------------------------- */

static void
match_press_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
  FpDevice *device = FP_DEVICE (source);
  PressData *d = g_task_get_task_data (G_TASK (res));
  GError *error = NULL;
  GError *retry = NULL;

  fpi_device_report_finger_status_changes (device, FP_FINGER_STATUS_NONE,
                                           FP_FINGER_STATUS_NEEDED);
  if (!g_task_propagate_boolean (G_TASK (res), &error))
    {
      if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_complete (device, error);
      else
        fpi_device_identify_complete (device, error);
      return;
    }

  fp_info ("best score %d, %s", d->score, d->match >= 0 ? "match" : "no match");
  if (d->match < 0 && !d->probe_ok)
    retry = fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);

  if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_VERIFY)
    {
      fpi_device_verify_report (device,
                                retry ? FPI_MATCH_ERROR :
                                d->match >= 0 ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                                NULL, retry);
      fpi_device_verify_complete (device, NULL);
    }
  else
    {
      GPtrArray *prints = NULL;

      fpi_device_get_identify_data (device, &prints);
      fpi_device_identify_report (device,
                                  d->match >= 0 ? g_ptr_array_index (prints, d->match) : NULL,
                                  NULL, retry);
      fpi_device_identify_complete (device, NULL);
    }
}

static GVariant *
print_data (FpPrint *print)
{
  GVariant *data = NULL;

  g_object_get (print, "fpi-data", &data, NULL);
  return data; /* NULL or a new reference */
}

static void
dev_verify_identify (FpDevice *device)
{
  GPtrArray *gallery = g_ptr_array_new_with_free_func ((GDestroyNotify) g_variant_unref);

  if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *print = NULL;
      GVariant *data;

      fpi_device_get_verify_data (device, &print);
      data = print_data (print);
      g_ptr_array_add (gallery, data ? data : g_variant_ref_sink (g_variant_new_boolean (FALSE)));
    }
  else
    {
      GPtrArray *prints = NULL;

      fpi_device_get_identify_data (device, &prints);
      for (guint i = 0; i < prints->len; i++)
        {
          GVariant *data = print_data (g_ptr_array_index (prints, i));

          g_ptr_array_add (gallery, data ? data : g_variant_ref_sink (g_variant_new_boolean (FALSE)));
        }
    }

  start_press (device, TRUE, gallery, match_press_done);
}

/* ---- GObject -------------------------------------------------------- */

static void
fpi_device_goodix521d_init (FpiDeviceGoodix521d *self)
{
}

static void
fpi_device_goodix521d_finalize (GObject *object)
{
  FpiDeviceGoodix521d *self = FPI_DEVICE_GOODIX521D (object);

  enroll_clear (self);
  tls_free (self);
  G_OBJECT_CLASS (fpi_device_goodix521d_parent_class)->finalize (object);
}

static void
fpi_device_goodix521d_class_init (FpiDeviceGoodix521dClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  G_OBJECT_CLASS (klass)->finalize = fpi_device_goodix521d_finalize;

  dev_class->id = "goodix521d";
  dev_class->full_name = "Goodix GF5298 (27c6:521d), SIGFM matcher";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = ENROLL_STAGES;
  dev_class->temp_hot_seconds = -1;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify_identify;
  dev_class->identify = dev_verify_identify;

  fpi_device_class_auto_initialize_features (dev_class);
}
