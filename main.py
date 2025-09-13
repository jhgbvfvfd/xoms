import os
import datetime
import pytz
import random
import string
import traceback
import requests
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from PIL import Image, ImageDraw, ImageFont
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask import request

# -----------------
# Configuration
# -----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your_super_secret_key_that_is_very_long_and_random'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

ROLE_PRICE = 30.0
VIP_DAYS = 7
PHONE_NUMBER = "0613364824"
SITE_NAME = "WACK SHOP"

# -----------------
# Database Model
# -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    is_premium = db.Column(db.Boolean, default=False)
    premium_expiry = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(255), nullable=True)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('login_logs', lazy=True))
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now(pytz.timezone('Asia/Bangkok')))

class RentalHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('rental_history', lazy=True))
    amount = db.Column(db.Float, nullable=False)
    duration_days = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now(pytz.timezone('Asia/Bangkok')))
    voucher_hash = db.Column(db.String(255), nullable=True)

# -----------------
# Admin Panel Views
# -----------------
class AdminAuthView(ModelView):
    def is_accessible(self):
        if 'is_admin' not in session or not session['is_admin']:
            return False
        return True

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin_login', next=request.url))

class UserAdminView(AdminAuthView):
    column_list = ('id', 'username', 'password', 'balance', 'is_premium', 'premium_expiry', 'is_admin', 'is_banned', 'ban_reason', 'last_ip')
    column_labels = {'last_ip': 'IP ล่าสุด'}
    column_editable_list = ('password', 'balance', 'is_premium', 'premium_expiry', 'is_admin', 'is_banned', 'ban_reason')
    column_searchable_list = ('username',)
    column_filters = ('is_premium', 'is_admin', 'is_banned')

    def on_model_change(self, form, model, is_created):
        # This will save the password as plain text
        if 'premium_expiry' in form.data:
            expiry_str = form.premium_expiry.data
            try:
                if isinstance(expiry_str, datetime.datetime):
                    tz = pytz.timezone('Asia/Bangkok')
                    model.premium_expiry = tz.localize(expiry_str)
                else:
                    pass
            except Exception as e:
                flash(f"Error updating expiry date: {e}", 'error')

    def _last_ip_formatter(self, context, model, name):
        last_login = LoginLog.query.filter_by(user_id=model.id).order_by(LoginLog.timestamp.desc()).first()
        return last_login.ip_address if last_login else 'N/A'
    
    column_formatters = {
        'last_ip': _last_ip_formatter
    }
        
class AdminIndex(AdminIndexView):
    @expose('/')
    def index(self):
        if not 'is_admin' in session or not session['is_admin']:
            return redirect(url_for('admin_login'))

        total_users = User.query.count()
        premium_users = User.query.filter_by(is_premium=True).count()
        total_rentals = RentalHistory.query.count()
        total_rentals_amount = db.session.query(db.func.sum(RentalHistory.amount)).scalar() or 0

        last_logins = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(5).all()

        return self.render('admin_dashboard.html', 
                           total_users=total_users, 
                           premium_users=premium_users, 
                           total_rentals=total_rentals,
                           total_rentals_amount=total_rentals_amount,
                           last_logins=last_logins,
                           site_name=SITE_NAME)

    @expose('/config', methods=['GET', 'POST'])
    def config(self):
        if not self.is_accessible():
            return redirect(url_for('admin_login'))
            
        if request.method == 'POST':
            global SITE_NAME, PHONE_NUMBER, ROLE_PRICE, VIP_DAYS
            SITE_NAME = request.form.get('site_name', SITE_NAME)
            PHONE_NUMBER = request.form.get('phone_number', PHONE_NUMBER)
            ROLE_PRICE = float(request.form.get('role_price', ROLE_PRICE))
            VIP_DAYS = int(request.form.get('vip_days', VIP_DAYS))
            
            flash('ตั้งค่าระบบเรียบร้อยแล้ว', 'success')
            return redirect(url_for('admin.config'))

        return self.render('admin_config.html',
                           site_name=SITE_NAME,
                           phone_number=PHONE_NUMBER,
                           role_price=ROLE_PRICE,
                           vip_days=VIP_DAYS)

# -----------------
# Utility Functions
# -----------------
def censor_last_word(text: str) -> str:
    parts = text.split()
    if not parts:
        return text
    last = parts[-1]
    if len(last) > 1:
        censored = last[0] + "*" * (len(last) - 1)
        parts[-1] = censored
    return " ".join(parts)

def format_thai_date(day: int, month: int, year: int) -> str:
    thai_months = [
        "", "ม.ค.", "ก.พ.", "มี.ค.", "เม.ย.", "พ.ค.", "มิ.ย.",
        "ก.ค.", "ส.ค.", "ก.ย.", "ต.ค.", "พ.ย.", "ธ.ค."
    ]
    return f"{day} {thai_months[month]} {year}"

# ... (render_wallet and topup_vip functions remain the same) ...
def render_wallet(transfer_name, receive_name, user_phone, receive_phone, transfer_amount):
    try:
        slip_path = "slipnew.png"
        if not os.path.exists(slip_path):
            print(f"Error: File not found at '{slip_path}'. Please make sure 'slipnew.png' is in the main directory.")
            return None

        image = Image.open(slip_path)
    except Exception as e:
        print(f"Error loading image: {e}")
        return None

    try:
        draw = ImageDraw.Draw(image)
        
        font_path_kanit = "static/fonts/Kanit-Regular.ttf"
        font_path_inter = "static/fonts/Inter_18pt-Regular.ttf"
        font_path_noto = "static/fonts/NotoSansThai-Regular.ttf"
        font_path_dm_sans = "static/fonts/DMSans-Black.ttf"
        
        if not all(os.path.exists(p) for p in [font_path_kanit, font_path_inter, font_path_noto, font_path_dm_sans]):
            print("Error: One or more font files are missing from 'static/fonts/' directory.")
            return None

        font_money = ImageFont.truetype(font_path_dm_sans, 60)
        font_user = ImageFont.truetype(font_path_kanit, 45)
        font_me = ImageFont.truetype(font_path_kanit, 45)
        font_phone = ImageFont.truetype(font_path_inter, 40)
        font_time = ImageFont.truetype(font_path_noto, 38)
        font_order = ImageFont.truetype(font_path_noto, 38)

        name_user_id = censor_last_word(transfer_name)
        name_me_id = receive_name
        phone_me_id = receive_phone
        money_id = transfer_amount

        thailand_timezone = pytz.timezone('Asia/Bangkok')
        current_time_thailand = datetime.datetime.now(thailand_timezone)
        time_str = current_time_thailand.strftime("%H:%M:%S")
        day = current_time_thailand.day
        month = current_time_thailand.month
        year = current_time_thailand.year

        text_money = f"{float(money_id):,.2f}"
        text_name_user = name_user_id
        text_name_me = name_me_id
        text_name_phone_user = f"{user_phone[:2]}*-***-{user_phone[6:]}"
        text_name_phone = f"{phone_me_id[:2]}*-***-{phone_me_id[6:]}"
        text_name_time = format_thai_date(day, month, year) + f" {time_str}"
        
        rand_order = random.randint(10000000000, 99999999999)
        text_name_order = f"500{rand_order}"

        text_position_money = (485, 227)
        text_position_user = (237, 400)
        text_position_me = (237, 670)
        text_position_phone_user = (450, 477)
        text_position_phone = (450, 742)
        text_position_time = (583, 863)
        text_position_order = (655, 933)

        text_color_money = (60, 50, 80)
        text_color_user = (50, 50, 50, 50)
        text_color_me = (50, 50, 50, 50)
        text_color_phone = (80, 80, 80)
        text_color_time = (50, 50, 50)
        text_color_order = (50, 50, 50)

        draw.text(text_position_money, text_money, font=font_money, fill=text_color_money)
        draw.text(text_position_user, text_name_user, font=font_user, fill=text_color_user)
        draw.text(text_position_me, text_name_me, font=font_me, fill=text_color_me)
        draw.text(text_position_phone_user, text_name_phone_user, font=font_phone, fill=text_color_phone)
        draw.text(text_position_phone, text_name_phone, font=font_phone, fill=text_color_phone)
        draw.text(text_position_time, text_name_time, font=font_time, fill=text_color_time)
        draw.text(text_position_order, text_name_order, font=font_order, fill=text_color_order)

        output_filename = f"slip_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}.png"
        output_path = os.path.join('static', output_filename)
        image.save(output_path)
        return output_filename
    
    except Exception as e:
        print("An error occurred during image rendering:")
        print(traceback.format_exc())
        return None

def topup_vip(voucher_link: str):
    if not voucher_link.startswith("https://gift.truemoney.com/campaign/?v="):
        return {"status": "error", "msg": "ลิงก์ไม่ถูกต้อง"}

    voucher_hash = voucher_link.split("v=")[-1]
    url = f"https://api.psnw.xyz/topup.php?voucher={voucher_hash}&phone={PHONE_NUMBER}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if data.get("status") == "success":
            amount = float(data["data"]["my_ticket"]["amount_baht"])
            if amount >= ROLE_PRICE:
                tz = pytz.timezone("Asia/Bangkok")
                expire_time = datetime.datetime.now(tz) + timedelta(days=VIP_DAYS)
                
                return {
                    "status": "success",
                    "amount": amount,
                    "expire": expire_time.strftime("%d/%m/%Y %H:%M:%S")
                }
            else:
                return {"status": "error", "msg": f"จำนวนเงิน {amount} ไม่ถึง {ROLE_PRICE} บาท"}
        else:
            return {"status": "error", "msg": data.get("msg", "เกิดข้อผิดพลาดจาก API")}
    except requests.exceptions.RequestException as e:
        print(f"API Connection Error: {e}")
        return {"status": "error", "msg": "ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์เติมเงินได้"}
    except (ValueError, KeyError) as e:
        print(f"API Data Error: {e}")
        return {"status": "error", "msg": "API ส่งข้อมูลที่ไม่ถูกต้องกลับมา"}
    except Exception as e:
        print(f"Unexpected Error: {e}")
        return {"status": "error", "msg": "เกิดข้อผิดพลาดที่ไม่คาดคิด"}

# -----------------
# Routes
# -----------------
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('account'))
    return render_template('index.html', site_name=SITE_NAME)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('ชื่อผู้ใช้นี้มีอยู่แล้ว', 'error')
            return redirect(url_for('register'))
        
        # Save password as plain text
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        
        session['username'] = new_user.username
        session['user_id'] = new_user.id
        session['is_admin'] = new_user.is_admin
        
        ip_address = request.remote_addr
        new_log = LoginLog(user_id=new_user.id, ip_address=ip_address)
        db.session.add(new_log)
        db.session.commit()

        flash('สมัครสมาชิกสำเร็จ! คุณเข้าสู่ระบบแล้ว', 'success')
        return redirect(url_for('account'))
    return render_template('register.html', site_name=SITE_NAME)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.is_banned:
            flash(f'คุณถูกแบนแล้ว: {user.ban_reason}', 'error')
            return redirect(url_for('login'))

        if user and user.password == password:
            session['username'] = user.username
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin

            ip_address = request.remote_addr
            new_log = LoginLog(user_id=user.id, ip_address=ip_address)
            db.session.add(new_log)
            db.session.commit()
            
            flash('เข้าสู่ระบบสำเร็จ', 'success')
            return redirect(url_for('account'))
        else:
            flash('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 'error')
    return render_template('login.html', site_name=SITE_NAME)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, is_admin=True).first()
        
        if user and user.password == password:
            session['username'] = user.username
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            
            flash('เข้าสู่ระบบ Admin สำเร็จ', 'success')
            return redirect(url_for('admin.index'))
        else:
            flash('ชื่อผู้ใช้หรือรหัสผ่าน Admin ไม่ถูกต้อง', 'error')
    return render_template('admin_login.html', site_name=SITE_NAME)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('ออกจากระบบสำเร็จ', 'success')
    return redirect(url_for('home'))

@app.route('/account')
def account():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(id=session['user_id']).first()
    
    if user.is_banned:
        flash(f'คุณถูกแบนแล้ว: {user.ban_reason}', 'error')
        session.pop('username', None)
        session.pop('user_id', None)
        session.pop('is_admin', None)
        return redirect(url_for('login'))
        
    is_expired = False
    time_remaining = None
    if user.is_premium and user.premium_expiry:
        thailand_timezone = pytz.timezone('Asia/Bangkok')
        now = datetime.datetime.now(thailand_timezone)
        
        if user.premium_expiry.tzinfo is None:
            user.premium_expiry = pytz.timezone("UTC").localize(user.premium_expiry)
        
        expiry_datetime_th = user.premium_expiry.astimezone(thailand_timezone)

        if now > expiry_datetime_th:
            user.is_premium = False
            user.premium_expiry = None
            db.session.commit()
            is_expired = True
        else:
            time_diff = expiry_datetime_th - now
            days = time_diff.days
            hours, remainder = divmod(time_diff.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            time_remaining = f"{days} วัน, {hours} ชั่วโมง, {minutes} นาที"

    return render_template('account.html', user=user, is_expired=is_expired, time_remaining=time_remaining, site_name=SITE_NAME)

@app.route('/topup_tmn', methods=['GET', 'POST'])
def topup_tmn():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        voucher_link = request.form['voucher_link']
        
        result = topup_vip(voucher_link)
        
        if result['status'] == 'success':
            user = User.query.filter_by(id=session['user_id']).first()
            user.is_premium = True
            expire_datetime_str = result['expire']
            expire_datetime_obj = datetime.datetime.strptime(expire_datetime_str, "%d/%m/%Y %H:%M:%S")
            user.premium_expiry = expire_datetime_obj
            
            new_rental = RentalHistory(user_id=user.id, amount=result['amount'], duration_days=VIP_DAYS, voucher_hash=voucher_link.split("v=")[-1])
            db.session.add(new_rental)
            db.session.commit()
            
            flash(f"เติมเงินสำเร็จ! ได้รับเงิน {result['amount']} บาท คุณสามารถใช้งานได้ {VIP_DAYS} วัน", 'success')
            return redirect(url_for('account'))
        else:
            flash(result['msg'], 'error')
    
    return render_template('topup_tmn.html', site_name=SITE_NAME, role_price=ROLE_PRICE, vip_days=VIP_DAYS)

@app.route('/fake_slip', methods=['GET', 'POST'])
def fake_slip():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(id=session['user_id']).first()

    if not user.is_premium:
        flash('คุณต้องเช่าระบบก่อนจึงจะใช้งานฟังก์ชันนี้ได้', 'error')
        return redirect(url_for('account'))

    slip_image = None
    if request.method == 'POST':
        try:
            transfer_name = request.form['transfer_name']
            receive_name = request.form['receive_name']
            user_phone = request.form['user_phone']
            receive_phone = request.form['receive_phone']
            transfer_amount = float(request.form['transfer_amount'])

            if not (len(user_phone) == 10 and len(receive_phone) == 10 and user_phone.isdigit() and receive_phone.isdigit()):
                flash('เบอร์โทรศัพท์ต้องมี 10 หลักและเป็นตัวเลขเท่านั้น', 'error')
            else:
                slip_image = render_wallet(transfer_name, receive_name, user_phone, receive_phone, transfer_amount)
                if slip_image:
                    flash('สร้างสลิปสำเร็จ!', 'success')
                else:
                    flash('เกิดข้อผิดพลาดในการสร้างสลิป', 'error')
        except ValueError:
            flash('จำนวนเงินต้องเป็นตัวเลขเท่านั้น', 'error')
        except Exception as e:
            print(f"An error occurred in fake_slip route: {e}")
            print(traceback.format_exc())
            flash('เกิดข้อผิดพลาดที่ไม่คาดคิดในการสร้างสลิป', 'error')

    return render_template('fake_slip.html', slip_image=slip_image, site_name=SITE_NAME)

# -----------------
# Admin Panel Setup
# -----------------
admin = Admin(app, name=SITE_NAME + ' Admin', index_view=AdminIndex(), template_mode='bootstrap3')
admin.add_view(UserAdminView(User, db.session, name='จัดการผู้ใช้', endpoint='user'))
admin.add_view(AdminAuthView(LoginLog, db.session, name='ประวัติการเข้าสู่ระบบ'))
admin.add_view(AdminAuthView(RentalHistory, db.session, name='ประวัติการเช่า'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(is_admin=True).first()
        if not admin_user:
            initial_admin = User(username='admin', password='admin_password', is_admin=True)
            db.session.add(initial_admin)
            db.session.commit()
            print("สร้างผู้ใช้ 'admin' ด้วยรหัสผ่าน 'admin_password' สำเร็จ")
            print("⚠️ กรุณาเปลี่ยนรหัสผ่านทันทีหลังล็อกอิน! ⚠️")
    app.run(debug=True)