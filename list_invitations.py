from app import app, Invitation, User, db

with app.app_context():
    invs = Invitation.query.order_by(Invitation.created_at.desc()).limit(50).all()
    if not invs:
        print('No invitations found')
    for inv in invs:
        inviter = User.query.get(inv.invited_by)
        print(f'id={inv.id} email={inv.email} token={inv.token} status={inv.status} expires_at={inv.expires_at} inviter={inviter.email if inviter else inv.invited_by}')
