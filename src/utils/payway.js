const crypto = require("crypto");

/**
 * Generates a timestamp string in the format YYYYMMDDHHmmss 
 * required by ABA PayWay.
 */
function getReqTime() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");

  return (
    d.getFullYear() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  );
}

/**
 * Signs the raw string using HMAC-SHA512 and your API Key.
 */
function signPayWay(raw) {
  return crypto
    .createHmac("sha512", process.env.ABA_PAYWAY_API_KEY)
    .update(raw)
    .digest("base64");
}

/**
 * Builds the hash for the checkout request.
 * Note: ABA requires a very specific field order.
 */
function buildPurchaseHash(payload) {
  const fields = [
    'req_time', 'merchant_id', 'tran_id', 'amount', 'items', 
    'shipping', 'firstname', 'lastname', 'email', 'phone', 
    'type', 'payment_option', 'return_url', 'cancel_url', 
    'continue_success_url', 'currency'
  ];

  // We map the fields and ensure null/undefined become empty strings
  // to prevent the string "null" from entering your hash.
  const raw = fields
    .map(field => (payload[field] !== undefined && payload[field] !== null ? payload[field] : ""))
    .join("");

  return signPayWay(raw);
}

/**
 * Encodes strings (like URLs or the Items list) to Base64.
 */
const encodeBase64 = (url) => {
  return Buffer.from(url).toString("base64");
};

/**
 * Hash for checking transaction status.
 */
function buildCheckTransactionHash({ req_time, merchant_id, tran_id }) {
  const raw = req_time + merchant_id + tran_id;
  return signPayWay(raw);
}

module.exports = {
  getReqTime,
  buildPurchaseHash,
  encodeBase64,
  buildCheckTransactionHash
};