from flask import Flask
from db import get_db, close_db
from os import close
from flask import g
from wtforms import Form, StringField, PasswordField, BooleanField, SelectField, SubmitField, TextAreaField, validators
from wtforms.fields.html5 import EmailField, IntegerField

def llenadatos(tabla):
    app = Flask(__name__)
    with app.app_context():
        condb = get_db()
        if condb is not None:
            if tabla == 'tipoids':
                datostabla = condb.execute(
                    'SELECT cod_id, nom_id FROM tipos_id'
                ).fetchall()
                return datostabla
        
            if tabla == 'listapaises':
                datostabla = condb.execute(
                'SELECT cod_pais, nom_pais FROM paises ORDER BY nom_pais'
                ).fetchall()
                return datostabla
        else:
            print('condb es None')
        close_db()
    return app


class Formulario_Login( Form ):
    alias = StringField('Usuario', 
    [ 
        validators.DataRequired('Dato requerido.'), 
        validators.Length(min=4,max=25)
    ] )
    clave = PasswordField('Contraseña',
    [ 
        validators.DataRequired(), 
        validators.Length(min=8,max=25)
    ])
    recordar = BooleanField('Recordarme')
    enviar = SubmitField('Ingresar a mi Cuenta')


class formulario_Nuevo_Usuario( Form ):
    tipoID = SelectField(u'Tipo ID', choices=llenadatos('tipoids'))

    numeroID = IntegerField('Número Identificación',
    [
        validators.DataRequired('Dato requerido'),
        validators.Length(min=6,max=11)
    ] )

    nombres = StringField('Nombre(s)',
    [
        validators.DataRequired('Dato requerido'),
        validators.Length(min=2,max=12)
    ] )

    apellidos = StringField('Apellido(s)',
    [
        validators.DataRequired('Dato requerido'),
        validators.Length(min=2,max=12)
    ] )

    email = StringField('Email',
    [
        validators.DataRequired('Dato requerido'),
        validators.Length(min=10,max=50)
    ] )

    pais = SelectField(u'País', choices=llenadatos('listapaises'), default = 'COL')

    alias = StringField('Nombre de Usuario',
    [
        validators.DataRequired('Dato requerido'),
        validators.Length(min=5,max=15)
    ] )

    clave = PasswordField('Password',
    [
        validators.DataRequired('Dato requerido'),
        validators.Length(min=8,max=20)
    ] )

    aceptapoldatos = BooleanField('Política de Datos', [ validators.DataRequired('Dato requerido'), ])
    aceptatyc = BooleanField('Términos y Condiciones', [ validators.DataRequired('Dato requerido'), ])
    enviar = SubmitField('Registrar Usuario')


class Formulario_Agregar_Producto( Form ):
    sku = StringField('SKU',
    [validators.DataRequired('Dato requerido')])

    nomprod = StringField('Nombre Producto',
    [validators.DataRequired('Dato requerido'),])

    talla = StringField('Talla',
    [validators.DataRequired('Dato requerido'),])

    color = StringField('Color',
    [validators.DataRequired('Dato requerido'),])

    material = StringField('Material',
    [validators.DataRequired('Dato requerido'),])

    descripcion = TextAreaField('Descripción Producto',
    [validators.DataRequired('Dato requerido'),])

    invent_inicial = IntegerField('Inventario Inicial',
    [validators.DataRequired('Dato requerido')])

    enviar = SubmitField('Guardar Producto')



