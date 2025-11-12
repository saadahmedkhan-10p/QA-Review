from app import app, Invitation, db
from datetime import datetime, timedelta

with app.app_context():
    inv = Invitation.query.first()
    if not inv:
        # Ensure there's at least one inviter user for foreign key - create admin if needed
        from app import User, generate_password_hash
        admin = User.query.filter_by(id=1).first()
        if not admin:
            admin = User(email='admin@qa.com', name='Admin', password_hash=generate_password_hash('admin123'), role='admin')
            db.session.add(admin)
            db.session.commit()
        inv = Invitation(email='test@example.com', invited_by=admin.id, token='testtoken', expires_at=datetime.utcnow()+timedelta(days=7))
        db.session.add(inv)
        db.session.commit()
    tpl = app.jinja_env.get_template('accept_invitation.html')
    # Create a form instance to pass
    from app import RegisterForm
    form = RegisterForm()
    form.email.data = inv.email
    rendered = tpl.render(invitation=inv, form=form)
    print('Rendered length:', len(rendered))
