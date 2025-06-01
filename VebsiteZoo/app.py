import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FloatField, TextAreaField, SelectField, BooleanField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from sqlalchemy.exc import IntegrityError
from flask_wtf.file import FileField, FileAllowed
import uuid
from sqlalchemy.orm import joinedload
from enum import Enum
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime


# Инициализация приложения
app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zoo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOADED_PHOTOS_DEST'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB


# Инициализация расширений
db = SQLAlchemy(app)

class OrderStatus(Enum):
    CREATED = 'Оформлен'
    PROCESSING = 'Собран'
    SHIPPED = 'Отправлен'
    CANCELLED = 'Отменен'

# Модели базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    cart_items = db.relationship('Cart', backref='user', cascade='all, delete-orphan')
    orders = db.relationship('Order', backref='user', cascade='all, delete-orphan')


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    subcategories = db.relationship('SubCategory', backref='category', cascade='all, delete-orphan')
    products = db.relationship('Product', backref='category', lazy=True)

class SubCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(200))
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    subcategory_id = db.Column(db.Integer, db.ForeignKey('sub_category.id'))  # Новое поле
    subcategory = db.relationship('SubCategory', backref='products')



class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    product = db.relationship('Product')


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.Enum(OrderStatus), default=OrderStatus.CREATED)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    items = db.relationship('OrderItem', backref='order', cascade='all, delete-orphan')


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    product = db.relationship('Product', backref='order_items')


class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='chats')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    messages = db.relationship('ChatMessage', backref='chat', cascade='all, delete-orphan')
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def serialize(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username,  # убедитесь, что у объекта user есть поле username
            'is_admin': self.user.is_admin,
            'last_activity': self.last_activity.isoformat(),
            'is_active': self.is_active,
            'unread_count': len([m for m in self.messages if not m.is_read])
        }


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='chat_messages')
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    is_read = db.Column(db.Boolean, default=False)

# Формы
class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[
        DataRequired(),
        Length(min=4, max=20)
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(),
        Length(min=6)
    ])
    submit = SubmitField('Зарегистрироваться')


class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class ProductForm(FlaskForm):
    name = StringField('Название ', validators=[DataRequired()], render_kw={"size": 38})
    image = FileField("Изображение", validators=[
        FileAllowed(["jpg", "jpeg", "png"], "Только JPG, JPEG, PNG!")
    ])
    description = StringField('Описание', render_kw={"size": 38})
    price = FloatField('Цена', validators=[DataRequired(), NumberRange(min=0.01)])
    stock = IntegerField('Количество', validators=[NumberRange(min=0)])
    category_id = SelectField('Категория', coerce=int, validators=[DataRequired()])
    subcategory_id = SelectField('Подкатегория', coerce=int)  # Новое поле
    submit = SubmitField('Сохранить')

class SubCategoryForm(FlaskForm):
    name = StringField('Название подкатегории', validators=[DataRequired()])
    category_id = SelectField('Категория', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Создать')

class CheckoutForm(FlaskForm):
    phone = StringField('Телефон', validators=[DataRequired(), Length(min=7, max=20)])
    address = StringField('Адрес', validators=[DataRequired(), Length(min=10)])
    comment = StringField('Комментарий к заказу', render_kw={"size": 31})
    submit = SubmitField('Оформить заказ')

class OrderStatusForm(FlaskForm):
    status = SelectField('Статус', choices=[(status.name, status.value) for status in OrderStatus])
    submit = SubmitField('Обновить статус')

class ProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[
        DataRequired(),
        Length(min=4, max=20)
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ], render_kw={"size": 35})
    submit = SubmitField('Обновить профиль')

class ChatForm(FlaskForm):
    message = StringField('Сообщение', validators=[DataRequired()])
    submit = SubmitField('Отправить')

# Вспомогательные функции
def is_admin():
    if 'user_id' not in session:

        return False
    user = User.query.get(session['user_id'])

    return user and user.is_admin

class CategoryForm(FlaskForm):
    name = StringField('Название категории', validators=[DataRequired()])
    submit = SubmitField('Сохранить')

class UserAdminForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    is_admin = BooleanField('Администратор')
    submit = SubmitField('Обновить')



@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return dict(current_user=user)

@app.context_processor
def inject_categories():
    categories = Category.query.options(
        db.joinedload(Category.subcategories)
    ).all()
    return dict(categories=categories)

@app.context_processor
def inject_cart_count():
    cart_count = 0
    if 'user_id' in session:
        cart_items = Cart.query.filter_by(user_id=session['user_id']).all()
        cart_count = sum(item.quantity for item in cart_items)  # Сумма количеств
    return dict(cart_count=cart_count)


# Глобальный словарь для отслеживания активных чатов
active_chats = {}


@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        return False
    user_id = session['user_id']
    join_room(f'user_{user_id}')
    emit('status', {'status': 'connected'})

@socketio.on('authenticate')
def handle_authenticate(data):
    user_id = data.get('user_id')
    if 'user_id' in session and session['user_id'] == user_id:
        join_room(f'user_{user_id}')

@socketio.on('join_chat')
def handle_join_chat(data):
    chat_id = data.get('chat_id')
    if chat_id:
        join_room(f'chat_{chat_id}')
        active_chats[session['user_id']] = chat_id


@socketio.on('message')
def handle_message(data):
    user_id = session.get('user_id')
    if not user_id:
        return

    chat_id = data.get('chat_id')
    message = data.get('message')

    if not chat_id or not message:
        return

    chat = Chat.query.get(chat_id)
    if not chat or (chat.user_id != user_id and not is_admin()):
        return

    user = User.query.get(user_id)
    new_message = ChatMessage(
        chat_id=chat_id,
        user_id=user_id,
        content=message
    )
    db.session.add(new_message)
    chat.last_activity = datetime.utcnow()
    db.session.commit()

    # Отправка сообщения всем участникам чата
    emit('new_message', {
        'chat_id': chat_id,
        'sender_id': user_id,
        'sender_name': user.username,
        'message': message,
        'timestamp': datetime.utcnow().isoformat()
    }, room=f'chat_{chat_id}')



@socketio.on('admin_join')
def handle_admin_join(data):
    chat_id = data.get('chat_id')
    if chat_id and is_admin():
        join_room(f'chat_{chat_id}')
        # Помечаем сообщения как прочитанные
        messages = ChatMessage.query.filter_by(chat_id=chat_id, is_read=False).all()
        for msg in messages:
            msg.is_read = True
        db.session.commit()
        emit('admin_joined', {'chat_id': chat_id}, room=f'chat_{chat_id}')


def get_active_chat(user_id):
    # Ищем последний активный чат пользователя
    chat = Chat.query.filter_by(user_id=user_id, is_active=True).order_by(Chat.last_activity.desc()).first()

    # Если нет активного чата - создаем новый
    if not chat:
        chat = Chat(user_id=user_id)
        db.session.add(chat)
        db.session.commit()

    return chat


@app.route('/admin/support')
def admin_support():
    if not is_admin():
        abort(403)

    chats = Chat.query.filter(
        Chat.is_active == True,
        ~Chat.user.has(is_admin=True)  # Исключаем чаты администраторов
    ).all()

    return render_template('admin/support.html', chats=chats)  # Создайте этот шаблон

@app.route('/admin/chats-data')
def admin_chats_data():
    if not is_admin():
        abort(403)

        # Фильтруем чаты, исключая администраторов
    chats = Chat.query.filter(
        Chat.is_active == True,
        ~Chat.user.has(is_admin=True)  # Исключаем чаты администраторов
    ).all()

    return jsonify([chat.serialize() for chat in chats])


@app.route('/support', methods=['GET', 'POST'])
def support():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    chat = get_active_chat(user_id)  # Используем новую функцию
    form = ChatForm()

    # Загружаем все сообщения чата
    messages = ChatMessage.query.filter_by(chat_id=chat.id).order_by(ChatMessage.timestamp.asc()).all()

    if form.validate_on_submit():
        try:
            # Создаем новое сообщение
            new_message = ChatMessage(
                chat_id=chat.id,
                user_id=user_id,
                content=form.message.data
            )
            db.session.add(new_message)
            chat.last_activity = datetime.utcnow()
            db.session.commit()

            # Обновляем через SocketIO
            socketio.emit('new_message', {
                'chat_id': chat.id,
                'sender_id': user_id,
                'sender_name': User.query.get(user_id).username,
                'message': form.message.data,
                'timestamp': datetime.utcnow().isoformat()
            }, room=f'chat_{chat.id}')

            return redirect(url_for('support'))

        except Exception as e:
            flash(f'Ошибка отправки сообщения: {str(e)}', 'danger')

    return render_template('support.html', chat=chat, messages=messages, form=form)


@app.route('/admin/support/<int:chat_id>', methods=['GET', 'POST'])
def admin_chat_detail(chat_id):
    if not is_admin():
        abort(403)

    user = User.query.get(session['user_id'])
    chat = Chat.query.options(
        db.joinedload(Chat.user),
        db.joinedload(Chat.messages)
    ).get_or_404(chat_id)

    form = ChatForm()

    if form.validate_on_submit():
        try:
            # Создание нового сообщения
            new_message = ChatMessage(
                chat_id=chat_id,
                user_id=session['user_id'],
                content=form.message.data
            )
            db.session.add(new_message)
            chat.last_activity = datetime.utcnow()
            db.session.commit()

            # Отправка через SocketIO
            socketio.emit('new_message', {
                'chat_id': chat_id,
                'sender_id': session['user_id'],
                'sender_name': user.username,
                'message': form.message.data,
                'timestamp': datetime.utcnow().isoformat()
            }, room=f'chat_{chat_id}')

            return redirect(url_for('admin_chat_detail', chat_id=chat_id))

        except Exception as e:
            flash(f'Ошибка отправки сообщения: {str(e)}', 'danger')

    return render_template('admin/chat_detail.html',
                           chat=chat,
                           form=form)

@app.route('/get-subcategories/<int:category_id>')
def get_subcategories(category_id):
    subcategories = SubCategory.query.filter_by(category_id=category_id).all()
    return jsonify([{'id': s.id, 'name': s.name} for s in subcategories])

# Новые маршруты для админ-панели
@app.route('/admin/categories')
def admin_categories():
    if not is_admin():
        abort(403)
    categories = Category.query.all()
    return render_template('admin/categories.html', categories=categories)

@app.route('/admin/category/new', methods=['GET', 'POST'])
def admin_new_category():
    if not is_admin():
        abort(403)
    form = CategoryForm()
    if form.validate_on_submit():
        category = Category(name=form.name.data)
        db.session.add(category)
        db.session.commit()
        return redirect(url_for('admin_categories'))
    return render_template('admin/edit_category.html', form=form)

@app.route('/admin/category/edit/<int:id>', methods=['GET', 'POST'])
def admin_edit_category(id):
    if not is_admin():
        abort(403)
    category = Category.query.get_or_404(id)
    form = CategoryForm(obj=category)
    if form.validate_on_submit():
        form.populate_obj(category)
        db.session.commit()
        return redirect(url_for('admin_categories'))
    return render_template('admin/edit_category.html', form=form)


# Страница создания подкатегории
@app.route('/admin/subcategory/new', methods=['GET', 'POST'])
def admin_new_subcategory():
    if not is_admin():
        abort(403)

    form = SubCategoryForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]  # Загрузка категорий

    if form.validate_on_submit():
        subcategory = SubCategory(
            name=form.name.data,
            category_id=form.category_id.data
        )
        db.session.add(subcategory)
        db.session.commit()
        flash('Подкатегория создана!', 'success')
        return redirect(url_for('admin_categories'))

    return render_template('admin/add_subcategory.html', form=form)


@app.route('/admin/subcategory/edit/<int:id>', methods=['GET', 'POST'])
def admin_edit_subcategory(id):
    if not is_admin():
        abort(403)

    subcategory = SubCategory.query.get_or_404(id)
    form = SubCategoryForm(obj=subcategory)

    # Загрузка категорий для выпадающего списка
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]

    if form.validate_on_submit():
        try:
            # Обновление данных подкатегории
            form.populate_obj(subcategory)
            db.session.commit()
            flash('Подкатегория успешно обновлена', 'success')
            return redirect(url_for('admin_categories'))

        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'danger')

    return render_template(
        'admin/edit_subcategory.html',
        form=form,
        subcategory=subcategory
    )

# Удаление подкатегории (опционально)
@app.route('/admin/subcategory/delete/<int:id>', methods=['POST'])
def admin_delete_subcategory(id):
    if not is_admin():
        abort(403)
    subcategory = SubCategory.query.get_or_404(id)
    db.session.delete(subcategory)
    db.session.commit()
    flash('Подкатегория удалена', 'success')
    return redirect(url_for('admin_categories'))

@app.route('/admin/category/<int:category_id>/add-subcategory', methods=['POST'])
def admin_add_subcategory(category_id):
    if not is_admin():
        abort(403)

    # Получаем данные из формы
    name = request.form.get('name')
    if not name:
        flash('Название подкатегории обязательно', 'danger')
        return redirect(url_for('admin_edit_category', id=category_id))

    # Создаем подкатегорию
    subcategory = SubCategory(name=name, category_id=category_id)
    db.session.add(subcategory)
    db.session.commit()

    flash('Подкатегория успешно создана', 'success')
    return redirect(url_for('admin_edit_category', id=category_id))

@app.route('/admin/users')
def admin_users():
    if not is_admin():
        abort(403)
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:id>', methods=['GET', 'POST'])
def admin_edit_user(id):
    if not is_admin():
        abort(403)
    user = User.query.get_or_404(id)
    form = UserAdminForm(obj=user)
    if form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
        return redirect(url_for('admin_users'))
    return render_template('admin/edit_user.html', form=form, user=user)

# Маршруты
@app.route('/')
def index():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    category_id = request.args.get('category', 0, type=int)
    subcategory_id = request.args.get('subcategory', type=int)

    new_category_id = 7

    query = Product.query
    # Если нет активных фильтров (категория/подкатегория/поиск), показываем новинки
    if not search and not category_id and not subcategory_id:
        query = query.filter(Product.category_id == new_category_id)
    else:
        # Старая логика фильтрации
        if search:
            query = query.filter(Product.name.ilike(f'%{search}%'))
        if category_id:
            query = query.filter(Product.category_id == category_id)
        if subcategory_id:
            query = query.filter(Product.subcategory_id == subcategory_id)

    products = query.paginate(page=page, per_page=24)

    categories = Category.query.all()

    return render_template('index.html',
                           user=user,
                           products=products,
                           categories=categories,
                           search=search,
                           category_id=category_id,
                           subcategory_id=subcategory_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = generate_password_hash(form.password.data)
            user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password
            )
            db.session.add(user)
            db.session.commit()
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Пользователь с таким именем или email уже существует!', 'danger')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session.clear()
            session['user_id'] = user.id  # Ключевая строка
            session.permanent = True
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))
        flash('Неверные данные', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    form = ProfileForm(obj=user)

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        db.session.commit()
        flash('Профиль обновлен', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', form=form, user=user)


@app.route('/product/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    return render_template('product_detail.html', product=product)


@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    product = Product.query.get_or_404(product_id)

    if product.stock < 1:
        flash('Товара нет в наличии', 'danger')
        return redirect(request.referrer)

    cart_item = Cart.query.filter_by(
        user_id=session['user_id'],
        product_id=product_id
    ).first()

    if cart_item:
        if cart_item.quantity < product.stock:
            cart_item.quantity += 1
        else:
            flash('Недостаточно товара на складе', 'danger')
            return jsonify({
        'success': True,
        'new_count': sum(item.quantity for item in user.cart_items)
    })
    else:
        cart_item = Cart(user_id=session['user_id'], product_id=product_id)
        db.session.add(cart_item)

    db.session.commit()
    return redirect(request.referrer)


@app.route('/cart')
def cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cart_items = Cart.query.filter_by(user_id=session['user_id']).all()
    valid_items = [item for item in cart_items if item.product is not None]
    total = sum(item.product.price * item.quantity for item in valid_items)

    return render_template('cart.html', cart_items=valid_items, total=total)


@app.route('/increase-quantity/<int:cart_id>', methods=['POST'])
def increase_quantity(cart_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cart_item = Cart.query.get_or_404(cart_id)
    if cart_item.user_id != session['user_id']:
        abort(403)

    if cart_item.quantity < cart_item.product.stock:
        cart_item.quantity += 1
        db.session.commit()

    return redirect(url_for('cart'))


@app.route('/decrease-quantity/<int:cart_id>', methods=['POST'])
def decrease_quantity(cart_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cart_item = Cart.query.get_or_404(cart_id)
    if cart_item.user_id != session['user_id']:
        abort(403)

    if cart_item.quantity > 1:
        cart_item.quantity -= 1
        db.session.commit()

    return redirect(url_for('cart'))

@app.route('/remove-from-cart/<int:cart_id>')
def remove_from_cart(cart_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cart_item = Cart.query.get_or_404(cart_id)
    if cart_item.user_id != session['user_id']:
        abort(403)

    db.session.delete(cart_item)
    db.session.commit()
    return redirect(url_for('cart'))


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    cart_items = Cart.query.filter_by(user_id=user.id).all()
    form = CheckoutForm()

    if not cart_items:
        return redirect(url_for('cart'))

    total = sum(item.product.price * item.quantity for item in cart_items)

    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Создаем заказ
            order = Order(
                user_id=user.id,
                total=total,
                phone=form.phone.data,
                address=form.address.data,
                comment=form.comment.data,
                status=OrderStatus.CREATED
            )
            db.session.add(order)

            # Фиксируем заказ, чтобы получить его ID
            db.session.flush()  # ← Ключевое исправление!

            # Добавляем элементы заказа
            for item in cart_items:
                order_item = OrderItem(
                    order_id=order.id,  # Теперь order.id доступен
                    product_id=item.product_id,
                    quantity=item.quantity,
                    price=item.product.price
                )
                db.session.add(order_item)
                item.product.stock -= item.quantity

            # Удаляем корзину и фиксируем всё
            Cart.query.filter_by(user_id=user.id).delete()
            db.session.commit()

            flash('Заказ успешно оформлен!', 'success')
            return redirect(url_for('profile'))

        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'danger')

    return render_template('checkout.html', cart_items=cart_items, form=form, total=total)

# Админ-роуты
@app.route('/admin/products')
def admin_products():
    if not is_admin():
        abort(403)

    products = Product.query.options(
        joinedload(Product.category),
        joinedload(Product.subcategory)
    ).all()
    return render_template('admin/products.html', products=products)


@app.route('/admin/product/edit/<int:id>', methods=['GET', 'POST'])
def admin_edit_product(id):
    if not is_admin():
        abort(403)

    product = Product.query.get_or_404(id)
    form = ProductForm(obj=product)
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    form.subcategory_id.choices = [(s.id, s.name) for s in SubCategory.query.all()]

    if form.validate_on_submit():
        try:
            form.populate_obj(product)
            db.session.commit()
            flash('Товар успешно обновлен', 'success')
            return redirect(url_for('admin_products'))

        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'danger')

    return render_template('admin/edit_product.html',
                         form=form,
                         product=product)

@app.route('/admin/product/new', methods=['GET', 'POST'])
def admin_new_product():
    if not is_admin():
        abort(403)

    form = ProductForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    form.subcategory_id.choices = [(s.id, s.name) for s in SubCategory.query.all()]

    if form.validate_on_submit():
        try:
            # Обработка изображения
            image_path = None
            if form.image.data:
                # Генерация уникального имени файла
                filename = secure_filename(form.image.data.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"

                # Пути для сохранения
                upload_dir = os.path.join(
                    app.config["UPLOADED_PHOTOS_DEST"],
                    "products"
                )
                os.makedirs(upload_dir, exist_ok=True)

                # Сохранение файла
                filepath = os.path.join(upload_dir, unique_filename)
                form.image.data.save(filepath)
                image_path = f"uploads/products/{unique_filename}"

            # Создание товара
            product = Product(
                name=form.name.data,
                image=image_path,
                description=form.description.data,
                price=form.price.data,
                stock=form.stock.data,
                category_id=form.category_id.data,
                subcategory_id=form.subcategory_id.data
            )

            db.session.add(product)
            db.session.commit()
            flash("Товар успешно добавлен", "success")
            return redirect(url_for("admin_products"))

        except Exception as e:
            db.session.rollback()
            flash(f"Ошибка: {str(e)}", "danger")

    return render_template("admin/edit_product.html", form=form)
# Удаление товара
@app.route('/admin/product/delete/<int:id>', methods=['POST'])
def admin_delete_product(id):
    if not is_admin():
        abort(403)
    product = Product.query.get_or_404(id)
    Cart.query.filter_by(product_id=product.id).delete()
    db.session.delete(product)
    db.session.commit()
    flash('Товар успешно удален', 'success')
    return redirect(url_for('admin_products'))

# Удаление категории
@app.route('/admin/category/delete/<int:id>', methods=['POST'])
def admin_delete_category(id):
    if not is_admin():
        abort(403)
    category = Category.query.get_or_404(id)
    # Проверка на наличие товаров в категории
    if category.products:
        flash('Нельзя удалить категорию с товарами', 'danger')
        return redirect(url_for('admin_categories'))
    db.session.delete(category)
    db.session.commit()
    flash('Категория удалена', 'success')
    return redirect(url_for('admin_categories'))

# Поиск пользователей
@app.route('/admin/users/search')
def admin_search_users():
    if not is_admin():
        abort(403)
    search_query = request.args.get('q', '').strip()
    if not search_query:
        return redirect(url_for('admin_users'))
    users = User.query.filter(
        (User.username.ilike(f'%{search_query}%')) |
        (User.email.ilike(f'%{search_query}%'))
    ).all()
    return render_template('admin/users.html', users=users)

# Поиск категорий
@app.route('/admin/categories/search')
def admin_search_categories():
    if not is_admin():
        abort(403)
    search_query = request.args.get('q', '').strip()
    if not search_query:
        return redirect(url_for('admin_categories'))
    categories = Category.query.filter(
        Category.name.ilike(f'%{search_query}%')
    ).all()
    return render_template('admin/categories.html', categories=categories)

# Поиск товаров
@app.route('/admin/products/search')
def admin_search_products():
    if not is_admin():
        abort(403)
    search_query = request.args.get('q', '').strip()
    if not search_query:
        return redirect(url_for('admin_products'))  # Возврат к полному списку
    products = Product.query.filter(Product.name.ilike(f'%{search_query}%')).all()
    return render_template('admin/products.html', products=products)

@app.route('/search')
def search():
    search_query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)

    # Поиск товаров
    products = Product.query.filter(
        Product.name.ilike(f'%{search_query}%')
    ).paginate(page=page, per_page=8)

    return render_template('search_results.html',
                           products=products,
                           search_query=search_query)


@app.route('/instant-search')
def instant_search():
    search_query = request.args.get('q', '')
    results = []

    if search_query:
        results = Product.query.filter(
            Product.name.ilike(f'%{search_query}%')
        ).limit(5).all()

    return jsonify({
        'html': render_template('instant_results.html', results=results)
    })


@app.route('/admin/orders')
def admin_orders():
    if not is_admin():
        abort(403)

    orders = Order.query.options(joinedload(Order.user)).order_by(Order.created_at.desc()).all()
    return render_template('admin/orders.html', orders=orders)


@app.route('/admin/order/<int:id>', methods=['GET', 'POST'])
def admin_order_detail(id):
    if not is_admin():
        abort(403)

    order = Order.query.options(
        joinedload(Order.items).joinedload(OrderItem.product)
    ).get_or_404(id)
    form = OrderStatusForm(obj=order)

    if form.validate_on_submit():
        try:
            form.populate_obj(order)
            db.session.commit()
            flash('Статус заказа обновлен', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'danger')

    return render_template('admin/order_detail.html', order=order, form=form)

# Обработчики ошибок
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return render_template('errors/500.html'), 500


# Создание таблиц
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    socketio.run(app, debug=True)