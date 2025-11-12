from app import app, send_invitation_email

with app.app_context():
    send_invitation_email('test+local@example.com', 'Tester', 'testtoken123', personal_message='Testing logging')
    print('Invoked send_invitation_email')
