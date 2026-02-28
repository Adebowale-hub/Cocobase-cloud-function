"""
ZedStore — Send OTP Cloud Function
Deploy this in the Cocobase Dashboard → Cloud Functions editor.

Accepts: { "email": "user@example.com" }
Returns: { "success": true, "otp": "123456", "message": "..." }

NOTE: The plain OTP is returned so that the calling server-side API
route can include it in the email.  The frontend never calls this
function directly — it goes through /api/send-otp instead.
"""

# ── Placeholder – email is sent by the Next.js API route ────────────
sendEmail = lambda **kwargs: None


def main():
    email = req.get("email")
    if not email:
        return {"error": "Email is required"}, 400

    # Validate email format
    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_pattern, email):
        return {"error": "Invalid email format"}, 400

    # Generate 6-digit OTP (cryptographically secure)
    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])

    # Hash OTP before storing (never store plain OTP)
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()

    # Set expiry to 5 minutes from now
    expires_at = (datetime.now() + timedelta(minutes=5)).isoformat()

    # Delete any existing OTP for this email (prevent stale entries)
    try:
        existing = db.query("otp_codes", email=email, limit=10)
        for doc in existing.get("data", []):
            db.delete_document("otp_codes", doc["id"])
    except Exception:
        pass  # Collection may not exist yet

    # Store new OTP record
    try:
        db.create_document("otp_codes", {
            "email": email,
            "otp_hash": otp_hash,
            "expires_at": expires_at,
            "verified": False,
            "attempts": 0
        })
    except Exception as e:
        return {"error": f"Failed to store OTP: {str(e)}"}, 500

    # Return OTP so the server-side API route can email it.
    # The frontend never sees this — it only calls /api/send-otp.
    return {
        "success": True,
        "otp": otp,
        "message": "OTP generated"
    }
