import hashlib
import os
from html import escape
from flask import Flask, request, render_template, make_response, send_file, redirect, url_for

app = Flask(__name__)

# Databáze vzkazů v paměti
all_messages = {}

# Načtení tajných údajů ze systému
ADMIN_USER = os.getenv('ADMIN_USER', 'superuser_fake')
ADMIN_PASS = os.getenv('ADMIN_PASS', 'superpassword_fake')
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN', 'supertoken_fake')

@app.route('/')
def index():
    auth_token = request.cookies.get('auth_session')
    student_ip = request.remote_addr
    flag_hash = hashlib.sha256(student_ip.encode()).hexdigest()[:12].upper()
    unique_flag = f"CTF{{XSS_MASTER_{flag_hash}}}"
    is_admin = (auth_token == ADMIN_TOKEN)

    msghtml = ""
    waiting_count = 0

    for msg_id in sorted(all_messages.keys(), reverse=True):
        msg_data = all_messages[msg_id]

        if not msg_data['reviewed']:
            waiting_count += 1

        # Student vidí jen své vzkazy + escapujeme obsah!
        if not is_admin and msg_data['ip'] == student_ip:
            status = "⏳ Čeká na kontrolu" if not msg_data['reviewed'] else "✅ Prověřeno administrátorem"
            color = "#fff3cd" if not msg_data['reviewed'] else "#d4edda"

            # === OPRAVA XSS ===
            safe_content = escape(msg_data["content"])

            msghtml += f'''
            <div style="border: 1px solid #ccc; padding: 10px; margin: 10px 0; background: {color}; border-radius: 5px;">
                <strong>Vzkaz #{msg_id}</strong> - {status}<br>
                <div style="margin-top: 5px; padding: 5px; background: rgba(255,255,255,0.5);">{safe_content}</div>
            </div>
            '''

    queue_info = f"<p>Aktuálně ve frontě na kontrolu: <strong>{waiting_count}</strong> vzkazů.</p>"

    return render_template('index.html',
                           is_admin=is_admin,
                           flag=unique_flag,
                           msghtml=msghtml,
                           queue_info=queue_info)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USER and password == ADMIN_PASS:
            resp = make_response(redirect(url_for('index')))

            # === OPRAVA SESSION HIJACKING ===
            resp.set_cookie(
                'auth_session',
                ADMIN_TOKEN,
                httponly=True,      # JavaScript k cookie nemá přístup
                samesite='Strict',  # Brání CSRF + některým XSS útokům
                path='/',
                secure=False        # False, protože běží na http
            )
            return resp

        return "Chybné jméno nebo heslo!", 401

    return '''
        <div style="max-width:300px; margin: 50px auto; font-family: sans-serif;">
            <h2>Admin Login</h2>
            <form method="post">
                Jméno: <input type="text" name="username" style="width:100%"><br><br>
                Heslo: <input type="password" name="password" style="width:100%"><br><br>
                <input type="submit" value="Přihlásit" style="width:100%; padding: 10px;">
            </form>
        </div>
    '''


@app.route('/post', methods=['POST'])
def post():
    content = request.form.get('content', '')
    student_ip = request.remote_addr
    if content:
        if len(content) > 2000:
            return "Vzkaz je příliš dlouhý!", 400

        msg_id = len(all_messages) + 1
        all_messages[msg_id] = {
            "ip": student_ip,
            "content": content,      # ukládáme původní (escapujeme až při výpisu)
            "reviewed": False
        }
    return 'Vzkaz odeslán. Admin ho brzy prověří. <a href="/">Zpět</a>'


@app.route('/admin/view/<int:msg_id>')
def admin_view(msg_id):
    auth_token = request.cookies.get('auth_session')
    if auth_token != ADMIN_TOKEN:
        return "Nepovolený přístup", 403

    msg = all_messages.get(msg_id)
    if not msg:
        return "Vzkaz neexistuje", 404

    msg['reviewed'] = True

    # === OPRAVA XSS v admin view ===
    safe_content = escape(msg['content'])

    return f"""
    <html>
        <head><title>Revize vzkazu</title></head>
        <body>
            <h1>Revize vzkazu č. {msg_id}</h1>
            <hr>
            <div id="content">
                {safe_content}
            </div>
        </body>
    </html>
    """


@app.route('/admin/next-job')
def next_job():
    for msg_id in sorted(all_messages.keys()):
        if not all_messages[msg_id]['reviewed']:
            return str(msg_id)
    return "none"


@app.route('/download-source')
def download():
    auth_token = request.cookies.get('auth_session')
    if auth_token == ADMIN_TOKEN:
        return send_file(__file__, as_attachment=True, download_name="main.py")
    return "Nepovolený přístup! Musíš být admin.", 403


@app.route('/download-template')
def download_template():
    auth_token = request.cookies.get('auth_session')
    if auth_token == ADMIN_TOKEN:
        template_path = os.path.join('templates', 'index.html')
        if os.path.exists(template_path):
            return send_file(template_path, as_attachment=True)
        else:
            return "Soubor index.html nebyl nalezen ve složce templates.", 404
    return "Nepovolený přístup!", 403


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
