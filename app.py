import os, datetime, yagmail, sqlite3, click, functools
from wtforms import form
from typing import TypeVar
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, current_app, g, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from yagmail import SMTP

from utils import isUsernameValid, isEmailValid, isPasswordValid
from db import get_db, close_db
from forms import Formulario_Login, formulario_Nuevo_Usuario, Formulario_Agregar_Producto

app = Flask(__name__)
app.secret_key = os.urandom(24)

def login_required(view):
    @functools.wraps( view ) # toma una función utilizada en un decorador y añadir la funcionalidad de copiar el nombre de la función.
    def wrapped_view(**kwargs):
        id_usuario = session.get('id_usuario')
        if id_usuario is None:
            g.user = None
            return redirect( url_for( 'login' ) ) # si no tiene datos, lo envío a que se loguee
        else:
            g.user = get_db().execute(
                    'SELECT id_usuario, alias, rol, nombres, apellidos, email, clave FROM usuarios WHERE id_usuario = ?', (id_usuario,) ).fetchone()
            close_db()
        return view( **kwargs )
    return wrapped_view


@app.before_request
def cargar_usuario_registrado():
    id_usuario = session.get('id_usuario')
    if id_usuario is None:
        g.user = None


@app.route('/')
@app.route('/index')
def index():
    id_usuario = session.get('id_usuario')
    if id_usuario is None:
        return redirect( url_for( 'login' ) )
    else: 
        return redirect( url_for( 'user_in' ) )


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Formulario_Login( request.form )
    if request.method == 'POST': #and form.validate():  
        usuario = request.form['alias']
        password = request.form['clave']
        error = None

        if error is None:
            condb = get_db()
            usuarioregistrado = condb.execute(
                'SELECT id_usuario, alias, clave, rol FROM usuarios WHERE alias = ?', (usuario,)
            ).fetchone()
            close_db()

            if usuarioregistrado is None:
                error = 'Usuario y/o contraseña no son correctos!'
                flash(error)
            else:
                usuariovalido = check_password_hash(usuarioregistrado[2], password)

                if not usuariovalido:
                    error = 'Usuario y/o contraseña no son correctos!'
                    flash(error)
                    return render_template("login.html", form=form, titulo = 'Login')
                else: 
                    session.clear()
                    session['id_usuario'] = usuarioregistrado[0] # con esto estoy guardando el id/num identificación del usuario
                    #guarda la fecha y hora del último acceso
                    fechor = datetime.datetime.now().strftime('%a %x, %X') #fecha/hora del sistema
                    condb = get_db()
                    condb.execute(
                        'UPDATE usuarios SET ultimoacceso = ? WHERE alias = ?', (fechor, usuario)
                    ).fetchone()
                    condb.commit()
                    close_db()

                    #Cuando confirma la sesión, crea una cookie del tipo ‘username’ y almacene el usuario.
                    if check_password_hash(usuarioregistrado[3], 'US'): #usuario
                        response = make_response( redirect( url_for( 'user_in' ) ) )
                    elif check_password_hash(usuarioregistrado[3], 'SA'): #superadmin
                        response = make_response( redirect( url_for( 'admin_in' ) ) )
                    elif check_password_hash(usuarioregistrado[3], 'AD'): #administrador
                        response = make_response( redirect( url_for( 'admin_in' ) ) )
                    response.set_cookie( 'username', usuario  ) # nombre de la cookie y su valor
                    return response

    # GET o hay errores:
    return render_template("login.html", form=form, titulo = 'Login')


@app.route('/logout')
def logout():
    session.clear()
    return redirect( url_for( 'login' ) )


@app.route('/registrarusuario', methods=['GET', 'POST'])
def registrarusuario():
    if g.user is not None:
        flash("Sesión ya iniciada, para registrar un nuevo usuario, primero cierre la sesión actual!")
        return redirect( url_for('user_in') )

    form = formulario_Nuevo_Usuario( request.form )
    sigue = 'S'
    if sigue == 'S':
        if request.method == 'POST':
            if form.cancelar.data:  #pulsaron 'Cancelar'
                return redirect (url_for('login'))
                
            tipoid = request.form['tipoID']
            numeroid = request.form['numeroID']
            nombres = request.form['nombres']
            apellidos = request.form['apellidos']
            email = request.form['email']
            pais = request.form['pais']
            alias = request.form['alias']
            clave = request.form['clave']

            error = None
            condb = get_db()

            if not isUsernameValid(alias): #usuario bien escrito
                error = "El usuario debe ser alfanumerico o incluir solo '.','_','-'"
                flash(error)
            else: #verificar usuario no esté registrado
                existe = condb.execute(
                    'SELECT * FROM usuarios WHERE alias = ?', (alias,)
                ).fetchone()
                if existe is not None:
                    error = "Usuario ya existe, pruebe agregarle números ;-) "
                    flash(error)

            if not isEmailValid(email): #email bien escrito
                error = "Correo inválido - no es el formato adecuado"
                flash(error)
            else: #verificar email no esté registrado
                existe = condb.execute(
                    'SELECT * FROM usuarios WHERE email = ?', (email,)
                ).fetchone()
                if existe is not None:
                    error = "Email ya registrado!"
                    flash(error)

            if not isPasswordValid(clave): #clave cumple requerimientos
                error = "La contraseña debe contener al menos una minúscula, una mayúscula, un número y 8 caracteres"
                flash(error)

            if error is not None:
                close_db()
                return render_template("registrarusuario.html", form=form, titulo = "Verifique y reintente")
            else:
                #cifrar contraseña y rol, generar fecha y hora
                pwdcifrado = generate_password_hash(clave)
                rolcifrado = generate_password_hash('US')
                fechor = datetime.datetime.now().strftime('%a %x, %X') #fecha/hora del sistema
                #guardar el registro en la tabla de usuarios
                condb.execute(
                    "INSERT INTO usuarios (id_usuario,tipo_id,nombres,apellidos,email,pais,alias,clave,rol,foto,registrado,ultimoacceso,aceptalegales) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (numeroid,tipoid,nombres,apellidos,email,pais,alias,pwdcifrado,rolcifrado,0,fechor,fechor,'SI')
                    )
                condb.commit()
                close_db()
                #Enviar un correo.
                subject=alias + ', Tu registro en ForEver 21'
                contents='<h2>Bienvenid@, Gracias por registrarte con nosotros!</h2> <br><br>Éstos son tus datos:<br><strong>Nombre de Usuario:</strong> {}<br><strong>Contraseña:</strong> {}<br><br>Guarda tus datos para poder ingresar a nuestra plataforma. <strong>¡Pronto actualizaremos el método de autenticación por email!</strong>'.format(alias,clave)
                yagmail.SMTP('forever21uninortemintic@gmail.com').send(email, subject, contents)
                flash('Revisa tu correo electrónico')
                return redirect( url_for( 'login' ) )
        #método GET
        return render_template("registrarusuario.html", form=form, titulo = "Registrar Nuevo Usuario")

 #   except:
 #       flash("¡Ups! Ha ocurrido un error, intentelo de nuevo.")
 #       return render_template("registrarusuario.html", form=form, titulo = "Verifique y reintente")


@app.route('/user_in', methods=['GET', 'POST'])
@login_required
def user_in():
    if check_password_hash(g.user[2], 'US'):
        #captura los productos de la tabla 'productos'
        condb = get_db()
        listaproductos = condb.execute(
            'SELECT sku, nomb_prod FROM productos'
        ).fetchall()
        close_db()

        return render_template("espaciousuario.html", usuario = g.user[1], titulo = "Espacio de Usuario", listaproductos = listaproductos)
    return redirect( url_for( 'logout' ) )


@app.route('/admin_in', methods=['GET', 'POST'] )
@login_required
def admin_in():
    if check_password_hash(g.user[2], 'AD'):
        tipo = '2'
    elif check_password_hash(g.user[2], 'SA'):
        tipo = '3'
    else:
        return redirect( url_for( 'logout' ) )

    return render_template("admindashboard.html", usuario = g.user[1], tipo = tipo )


@app.route('/calificaproducto', methods=['GET', 'POST'])
@login_required
def calificaproducto():
    usuerprog = g.user[1]
    if request.method == 'POST':
        prodSel = request.form['prodSel']
        condb = get_db()
        #busco el producto
        detprod = condb.execute(
            'SELECT sku, id_prod, nomb_prod, desc_prod, tall_prod, colo_prod, mate_prod, fot1_prod, fot2_prod, fot3_prod, invi_prod, cat1_prod, cat2_prod, cat3_prod FROM productos WHERE sku = ?', (prodSel,)
        ).fetchone()
        if detprod is not None:
            #capturo los comentarios de ese producto en la tabla usu_prod
            comentarios = condb.execute(
                'SELECT usuario, U.foto, comentario, califica, fecha FROM usu_prod, usuarios U WHERE (producto = ? AND usuario IS NOT ? AND comentario IS NOT NULL AND comentario IS NOT "") AND (U.alias = usuario) ORDER BY fecha DESC', (detprod[1], usuerprog)
            ).fetchall()
            #ahora calculo la calificación promedio de la misma tabla (usu_prod)
            calprom = condb.execute(
                'SELECT avg(califica) FROM usu_prod WHERE producto = ? AND califica IS NOT NULL AND califica > 0', (detprod[1],)
            ).fetchone()
            #finalmente, busco si ya hay registro en la misma tabla del mismo usuario de ese producto para precargarlos en la página de calificación de producto (lo que comentó, si ya está en la lista de deseos y la calificación que ya le haya dado a es producto)
            caliprevia = condb.execute(
                'SELECT comentario, califica, fecha, lista_deseos FROM usu_prod WHERE usuario = ? AND producto = ?', (usuerprog, detprod[1])
            ).fetchone()
            close_db()
            if calprom[0] is None:
                calprom = [0]
        else: 
            error = "Ocurrió un error de búsqueda del producto seleccionado - SKU: "+prodSel
            flash(error)
            close_db()
            return redirect( url_for('user_in') )

        return render_template("calificaproducto.html", usuario = usuerprog, detprod = detprod, comentarios = comentarios, calprom = round(calprom[0],2), caliprevia = caliprevia)
    return redirect(url_for('logout'))


@app.route('/guardarprefprod', methods=['GET', 'POST'])
@login_required
def guardarprefprod():
    usuerprog = g.user[1]
    if request.method == 'POST':
        prodSel = request.form['prodSel']
        agregarlisdeseos = request.form.get("agregarlisdeseos") #si no está seleccionado, manda error
        calificaproducto = request.form['calificaproducto']
        comentarproducto = request.form['comentarproducto']
        #verifico la variable 'agregarlisdeseos' para convertirla en [1] ó [0] (Boleano)
        if agregarlisdeseos is None:
            agregarlisdeseos = 0
        else:
            agregarlisdeseos = 1
        fechor = datetime.datetime.now().strftime('%a %x, %X') #fecha/hora del sistema
        condb = get_db()
        #busco en la tabla usu_prod si hay registro para actualizar, si no hay, inserto uno nuevo
        regexistente = condb.execute(
            'SELECT usuario, producto FROM usu_prod WHERE usuario = ? AND producto = ?', (usuerprog, prodSel)
        ).fetchone()
        if regexistente is None: #no hay registro, va a insertar nuevo
            condb.execute(
                'INSERT INTO usu_prod (usuario,producto, comentario, califica, lista_deseos, fecha) VALUES (?,?,?,?,?,?)', (usuerprog, prodSel, comentarproducto, calificaproducto, agregarlisdeseos, fechor)
            )
        else: #hay registro, se actualiza
            condb.execute(
                'UPDATE usu_prod SET comentario = ?, califica = ?, lista_deseos = ?, fecha = ? WHERE usuario = ? AND producto = ?', (comentarproducto, calificaproducto, agregarlisdeseos, fechor, usuerprog, prodSel)
            )
        condb.commit()
        close_db()
        flash('Información actualizada - ¡Gracias por hacernos saber cómo lo estamos haciendo!')
        return redirect( url_for('user_in') )
    return redirect(url_for('logout'))


@app.route('/admcomentarios', methods=['GET', 'POST'])
@login_required
def admcomentarios():
    usuerprog = g.user[1]
    #capturo registros asociados al usuario en la tabla usu_prod que tengan comentarios
    condb = get_db()
    produsuario = condb.execute(
        'SELECT producto, comentario, fecha, P.sku, P.nomb_prod, P.colo_prod, P.tall_prod, P.mate_prod, P.desc_prod FROM usu_prod, productos P WHERE (usuario = ? AND comentario IS NOT NULL AND comentario IS NOT "") AND (P.id_prod = producto) ORDER BY fecha DESC', (usuerprog,)
    ).fetchall()
    close_db()
    if not produsuario: #no hay registros para ese usuario
        flash('No tienes comentarios! - Selecciona un producto para que lo comentes!')
        return redirect(url_for('user_in'))

    return render_template("admcomentarios.html", usuario = usuerprog, titulo = "Comentarios", produsuario = produsuario)


@app.route('/editacomentario', methods=['GET', 'POST'])
@login_required
def editacomentario():
    usuerprog = g.user[1]
    if request.method == 'POST':
        prodSel = request.form['prodSel']
        btneditcomm = request.form['btneditcomm']
        editarcomentario = request.form['editarcomentario']
        fechor = datetime.datetime.now().strftime('%a %x, %X') #fecha/hora del sistema
        condb = get_db()
        if btneditcomm == 'Eliminar':  #pulsaron 'Borrar comentario'
            editarcomentario = None

        condb.execute(
            'UPDATE usu_prod SET comentario = ?, fecha = ? WHERE usuario = ? AND producto = ?', (editarcomentario, fechor, usuerprog, prodSel)
            )
        condb.commit()
        close_db()
        flash('¡Información actualizada!')
        return redirect( url_for('user_in') )
    return redirect(url_for('logout'))


@app.route('/admlistadeseos', methods=['GET', 'POST'])
@login_required
def admlistadeseos():
    usuerprog = g.user[1]
    #capturo registros asociados al usuario en la tabla usu_prod que estén en la lisa de deseos
    condb = get_db()
    produsuario = condb.execute(
        'SELECT producto, califica, lista_deseos, fecha, P.sku, P.nomb_prod, P.colo_prod, P.tall_prod, P.mate_prod, P.desc_prod FROM usu_prod, productos P WHERE (usuario = ? AND lista_deseos = 1) AND (P.id_prod = producto) ORDER BY fecha DESC', (usuerprog,)
    ).fetchall()
    close_db()
    if not produsuario: #no hay registros para ese usuario
        flash('Tu lista de deseos está vacía!! - Selecciona un producto y si te gusta, lo agregas a tu lista! ;-) ')
        return redirect(url_for('user_in'))

    return render_template("admlistadeseos.html", usuario = usuerprog, titulo = 'Lista Deseos', produsuario = produsuario)


@app.route('/editalistadeseos', methods=['GET', 'POST'])
@login_required
def editalistadeseos():
    usuerprog = g.user[1]
    if request.method == 'POST':
        prodSel = request.form['prodSel']
        btneditlide = request.form['btneditlide']
        calificaproducto = request.form['calificaproducto']
        mantienelistadeseos = 1
        fechor = datetime.datetime.now().strftime('%a %x, %X') #fecha/hora del sistema
        condb = get_db()
        if btneditlide == 'Eliminar':  #pulsaron 'Borrar de la lista de deseos'
            calificaproducto = None
            mantienelistadeseos = 0
        condb.execute(
            'UPDATE usu_prod SET califica = ?, lista_deseos = ?, fecha = ? WHERE usuario = ? AND producto = ?', (calificaproducto, mantienelistadeseos, fechor, usuerprog, prodSel)
            )
        condb.commit()
        close_db()
        flash('¡Información actualizada!')
        return redirect( url_for('user_in') )
    return redirect(url_for('logout'))

@app.route('/agregarproducto', methods=['GET', 'POST'])
def agregarproducto():
        form = Formulario_Agregar_Producto( request.form )
        if request.method == 'POST':       
 #           usuario = request.form['usuario']
 #           email = request.form['email']
 #           password = request.form['password']
 #           nombres = request.form['nombres'] 

            error = None
            
            #1. Validar campos
 #           if not isUsernameValid(usuario):
 #               # Si está mal.
 #               error = "El usuario debe ser alfanumerico o incluir solo '.','_','-'"
 #               flash(error)
 #           if not isEmailValid(email):
 #               # Si está mal.
 #               error = "Correo invalido"
 #               flash(error)
 #           if not isPasswordValid(password):
 #               # Si está mal.
 #               error = "La contraseña debe contener al menos una minúscula, una mayúscula, un número y 8 caracteres"
 #               flash(error)

            if error is not None:
                # Ocurrió un error
                return render_template("agregarproducto.html", form=form, titulo = "Verifique y reintente")
            else:
                #2. Guardar producto

                flash('Producto guardado')

                #3. redirect para ir a otra URL
                return redirect( url_for( 'admin_in', usuario = 'alejo' ) )

        #método GET
        return render_template("agregarproducto.html", form=form, titulo = "Agregar Producto")


@app.route('/editarproducto', methods=['GET', 'POST'])
def editarproducto():
    return render_template("editarproducto.html", usuario = 'alejo')


@app.route('/eliminarproducto', methods=['GET', 'POST'])
def eliminarproducto():
    return render_template("eliminarproducto.html", usuario = 'alejo')


@app.route('/pruebas')
def pruebas():
    condb = get_db()
    if condb is not None:
        lista = condb.execute(
            'SELECT alias, clave, rol FROM usuarios'
        ).fetchall()
        close_db()
        nueva = []
        for elemento in lista:
            nueva.append(["Alias: "+elemento[0], "Clave: "+elemento[1], "Rol: "+elemento[2]])

        return render_template('pruebas.html', lista = nueva)
    else:
        print('condb es None')
        return render_template('pruebas.html', lista = 'None')



