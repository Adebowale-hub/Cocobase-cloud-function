"""
ZedStore — Verify OTP Cloud Function
Deploy this in the Cocobase Dashboard → Cloud Functions editor.

Accepts: { "email": "user@example.com", "otp": "123456", "new_password": "optional" }
Returns: { "success": true, "verified": true } or { "success": true, "password_reset": true }
"""

def main():
    email = req.get("email")
    otp = req.get("otp")
    new_password = req.get("new_password")

    if not email or not otp:
        return {"error": "Email and OTP are required"}, 400

    # Find stored OTP record for this email
    # If new_password is provided, the OTP was already verified in step 1,
    # so look for verified=True.  Otherwise look for unverified records.
    look_for_verified = True if new_password else False
    record = None
    try:
        results = db.query("otp_codes", email=email, limit=10)
        for doc in results.get("data", []):
            if doc.get("verified", False) == look_for_verified:
                record = doc
                break
    except Exception:
        pass

    if not record:
        return {"error": "No pending OTP found. Please request a new one."}, 400

    # Check attempts (max 5 to prevent brute-force)
    attempts = record.get("attempts", 0)
    if attempts >= 5:
        db.delete_document("otp_codes", record["id"])
        return {"error": "Too many attempts. Please request a new OTP."}, 429

    # Increment attempt counter
    db.update_document_fields("otp_codes", record["id"], {
        "attempts": attempts + 1
    })

    # Check expiry (5 minute window)
    expires_at = datetime.fromisoformat(record["expires_at"])
    if datetime.now() > expires_at:
        db.delete_document("otp_codes", record["id"])
        return {"error": "OTP has expired. Please request a new one."}, 400

    # Verify OTP hash
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    if otp_hash != record["otp_hash"]:
        remaining = 5 - (attempts + 1)
        return {"error": f"Invalid OTP code. {remaining} attempts remaining."}, 400

    # OTP is valid — mark as verified
    db.update_document_fields("otp_codes", record["id"], {
        "verified": True
    })

    # If new_password is provided, reset the password in one step
    if new_password:
        if len(new_password) < 6:
            return {"error": "Password must be at least 6 characters"}, 400

        try:
            results = db.query("users", email=email, limit=1)
            user = results.get("data", [None])[0] if results.get("data") else None
        except Exception:
            user = None

        if user:
            db.update_document_fields("users", user["id"], {"password": new_password})

        # Clean up OTP record after successful password reset
        db.delete_document("otp_codes", record["id"])

        return {
            "success": True,
            "password_reset": True,
            "message": "Password has been reset successfully"
        }

    # OTP verified, but no password change yet
    return {
        "success": True,
        "verified": True,
        "message": "OTP verified successfully"
          }
