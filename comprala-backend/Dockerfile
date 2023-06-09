# Usa una imagen base de Python
FROM python:3.10.5

# Instala dependencias de sistema
RUN apt-get update && apt-get install -y openssh-client

#Pertmite que la salida de la consola se muestre en tiempo real
ENV PYTHONUNBUFFERED 1

# Crea y establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos de requerimientos y los instala
COPY ./requirements.txt /app/requirements.txt

# Instala las dependencias de Python
RUN pip install -r requirements.txt

# Copia todo el proyecto al directorio de trabajo en el contenedor
COPY ./comprala /app/

# Ejecuta los comandos para migrar la base de datos y recoger los archivos estáticos

# RUN python manage.py makemigrations
# RUN python manage.py migrate
# RUN python manage.py collectstatic --noinput

CMD python manage.py runserver 127.0.0.1:8000
