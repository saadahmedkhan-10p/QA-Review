from app import app, db, Invitation, send_invitation_email

TOKEN = 'bimzDHv7KkSEkPUhoSPR97ZtWbNeWTXtiEewLGhHaiU'

with app.app_context():
    inv = Invitation.query.filter_by(token=TOKEN).first()
    if not inv:
        print('Invitation with token not found')
    else:
        inviter_name = inv.inviter.name if inv.inviter else 'Admin'
        print(f"Found invitation for {inv.email}, inviter: {inviter_name}, token: {inv.token}")
        send_invitation_email(inv.email, inviter_name, inv.token, personal_message='Resending invitation via script')
        print('Send invoked (email will be sent asynchronously or logged if not configured).')
