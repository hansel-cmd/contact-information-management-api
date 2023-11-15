# Use an official Python runtime as a parent image
FROM python:3.11.5

# Set environment variables
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

# Set the working directory to the Django project directory
# WORKDIR /app/backend

RUN python backend/manage.py makemigrations
RUN python backend/manage.py migrate

# Make port 8000 available to the world outside this container
EXPOSE 8000

CMD [ "python", "backend/manage.py", "runserver", "0.0.0.0:8000" ]