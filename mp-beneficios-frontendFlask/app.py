from flask import Flask, render_template, request, redirect, url_for, session, flash
from config import Config
import requests
import datetime
from datetime import datetime, date

app = Flask(__name__)
app.config.from_object(Config)

# API = app.config["BACKEND_URL"]
API = "https://gestorbeneficiosv0-3.onrender.com";

#---------------------------------- Helpers ----------------------------------#
def auth_headers():
    token = session.get("access_token")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}

def parse_requests(requests):
    """Ajusta el formato de las fechas en las solicitudes."""
    parsed = []
    for req in requests:
        if isinstance(req['created_at'], str):
            try:
                # Ajusta el formato al que realmente recibes
                # req['Fecha'] = datetime.fromisoformat(req['created_at']).strftime("%d/%m/%Y")
                req['Fecha'] = str(req['created_at']).split('T')[0]  
            except ValueError:
                req['Fecha'] = None
        parsed.append(req)
    return parsed

#---------------------------------- Routes ----------------------------------#

@app.route("/")
def index():
    # Simple health message from backend root
    try:
        r = requests.get(f"{API}/")
        backend_message = r.json().get("message", "Backend disponible")
    except Exception:
        backend_message = "Backend no disponible"
    return render_template("index.html", backend_message=backend_message)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        payload = {
            "cedula": request.form.get("nro_documento", "").strip(),
            "name": request.form.get("name", "").strip(),
            "email": request.form.get("email", "").strip(),
            "password": request.form.get("password", ""),
            "rol": request.form.get("rol","").strip(),
            "user_status":"activo"
        }
        try:
            r = requests.post(f"{API}/register", json=payload)
            if r.status_code == 200:
                data = r.json()
                session["access_token"] = data["access_token"]
                session["user"] = data["user"]
                flash("Registro exitoso. Bienvenido.", "success")
                user_rol = session["user"]["rol"]
                if user_rol == "Usuario":
                    return redirect(url_for("dashboard"))
                else:
                    return redirect(url_for("tiendas"))
            else:
                flash(r.json().get("detail", "Error de registro"), "error")
        except Exception as e:
                flash(f"Error conectando al backend: {e}", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        payload = {
            "email": request.form.get("email", "").strip(),
            "password": request.form.get("password", "")
        }
        try:
            r = requests.post(f"{API}/login", json=payload)
            if r.status_code == 200:
                data = r.json()
                session["access_token"] = data["access_token"]
                session["user"] = data["user"]
                flash("Inicio de sesión exitoso.", "success")
                if session["user"]["rol"] == "Usuario":
                    return redirect(url_for("dashboard"))
                else:
                    return redirect(url_for("tiendas"))
            else:
                flash(r.json().get("detail", "Credenciales incorrectas"), "error")
        except Exception as e:
            flash(f"Error conectando al backend: {e}", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("index"))

@app.route("/tiendas", methods=["GET"])
def tiendas():
    # Require auth
    if "access_token" not in session:
        flash("Por favor inicia sesión.", "warning")
        return redirect(url_for("login"))
    requests_list = []
    # Fetch user requests
    try:
        r = requests.get(f"{API}/request_tiendas", headers=auth_headers())
        if r.status_code == 200:
            requests_list = r.json()
        else:
            flash(r.json().get("detail", "No se pudieron obtener las solicitudes"), "error")
    except Exception as e:
        flash(f"Error, no se puede recuperar los datos en este momento: {e}", "error")
    return render_template("tiendas.html", user=session.get("user"), requests_list= requests_list, API=API)

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    # Require auth
    if "access_token" not in session:
        flash("Por favor inicia sesión.", "warning")
        return redirect(url_for("login"))

    requests_list = []
    # Fetch user requests
    try:
        r = requests.get(f"{API}/request", headers=auth_headers())
        if r.status_code == 200:
            requests_list = r.json()
        else:
            flash(r.json().get("detail", "No se pudieron obtener las solicitudes"), "error")
    except Exception as e:
        flash(f"Error, no se puede recuperar los datos en este momento: {e}", "error")

    # Create new request
    if request.method == "POST":
        benefit_type = request.form.get("benefit_type", "").strip()
        if benefit_type:
            try:
                r = requests.post(
                    f"{API}/request",
                    json={"benefit_type": benefit_type},
                    headers=auth_headers()
                )
                if r.status_code == 200:
                    flash("Solicitud creada.", "success")
                    return redirect(url_for("dashboard"))
                else:
                    # Backend returns detail for duplicate on the same day
                    flash(r.json().get("detail", "No se pudo crear la solicitud"), "error")
            except Exception as e:
                flash(f"Error conectando al backend: {e}", "error")

    return render_template("dashboard.html", user=session.get("user"), requests_list=parse_requests(requests_list), API=API)

if __name__ == "__main__":
    app.run(debug=True)