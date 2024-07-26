
from flask import Flask, json, jsonify, request, send_file, session
from flask_cors import CORS, cross_origin
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io
from datetime import datetime, timedelta, timezone
from models import db,User
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity, unset_jwt_cookies, jwt_required, JWTManager
import subprocess


app = Flask(__name__)

app.config['SECRET_KEY']='cairocoders-ednalan'
app.config["JWT_ACCESS_TOKEN_EXPIRES"]=timedelta(hours=1)
jwt=JWTManager(app)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///flaskdb.db'

SQLALCHEMY_TRACK_MODIFICATIONS=False
SQLALCHEMY_ECHO=True

bcrypt=Bcrypt(app)
CORS(app, supports_credentials=True)  
db.init_app(app)

with app.app_context():
    db.create_all()


@app.route("/signup", methods=["POST"])
def signup():
    email=request.json["email"]
    password=request.json["password"]
    about=request.json["about"]
    name=request.json["name"]

    user_exists=User.query.filter_by(email=email).first() is not None
 

    if user_exists:
        return jsonify({"error": "Email already exists"}), 409
    
    hashed_password=bcrypt.generate_password_hash(password)
    new_user=User(name=name,email=email, password=hashed_password, about=about)
    db.session.add(new_user)
    db.session.commit()


    return jsonify({
        "id": new_user.id,
        "email":new_user.email 
    }) 

@app.route("/logintoken", methods=["POST"])
def create_token():
    email=request.json.get("email",None)
    password=request.json.get("password",None)

    user=User.query.filter_by(email=email).first()
 

    if user is None:
        return jsonify({"error": "Wrong email or passwords"}),401
    
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error":"Unauthorized"}), 401
    
    access_token=create_access_token(identity=email)
    return jsonify({
        "email": email,
        "access_token": access_token
    })
   
@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp=get_jwt()["exp"]
        now= datetime.now(timezone.utc)
        target_timestamp= datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp>exp_timestamp:
            access_token=create_access_token(identity=get_jwt_identity())
            data=response.get_json()
            if type(data) is dict:
                data["access_token"]=access_token
                response.data=json.dumps(data)
        return response

    except(RuntimeError, KeyError):
        return response
    
@app.route("/logout", methods=["post"])
def logout():
    response= jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response

    
@app.route('/profile/<getemail>')
@jwt_required()
def my_profile(getemail):
    print(getemail)
    if not getemail:
        return jsonify({"error": "Unauthorizes Access"}), 401
    
    user= User.query.filter_by(email=getemail).first()

    response_body ={
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "about": user.about
    }

    return response_body


@app.route('/execute', methods=['POST'])
def execute_code():
    data = request.json
    code = data.get('code')
    inputs = data.get('inputs', [])
    
    try:
        # Écriture du code dans un fichier temporaire
        with open('temp.py', 'w') as f:
            f.write(code)

        # Préparation des entrées utilisateur
        input_data = "\n".join(inputs)
        
        # Exécution du code Python
        result = subprocess.run(
            ['python', 'temp.py'],
            input=input_data,
            text=True,
            capture_output=True,
            check=True
        )
        return jsonify({'output': result.stdout})
    except subprocess.CalledProcessError as e:
        return jsonify({'output': e.output}), 400


@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    text = request.form.get('text', '')

    
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    text_object = p.beginText(100, 750)
    text_object.setFont("Helvetica", 12)
    
    max_width = 500  
    line_spacing = 14  # Espace entre les lignes
    x, y = text_object.getCursor()

    lines = text.split('\n')

    for line in lines:
        words = line.split()
        current_line = ""
        
        for word in words:
            if p.stringWidth(current_line + word) < max_width:
                current_line += word + " "
            else:
                text_object.textLine(current_line.strip())
                current_line = word + " "
                y -= line_spacing
                if y < 40:  # Si on atteint le bas de la page
                    p.drawText(text_object)
                    p.showPage()
                    text_object = p.beginText(100, 750)
                    text_object.setFont("Helvetica", 12)
                    y = 750
        
        if current_line: 
            text_object.textLine(current_line.strip()) 
            y -= line_spacing
            if y < 40:  # Si on atteint le bas de la page
                p.drawText(text_object)
                p.showPage()
                text_object = p.beginText(100, 750)
                text_object.setFont("Helvetica", 12)
                y = 750

    p.drawText(text_object)
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='output.pdf', mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True)