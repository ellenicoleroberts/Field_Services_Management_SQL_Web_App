FROM python:3.9.13-alpine

# Maintainer info
LABEL maintainer="your-email"

# Make working directories
RUN  mkdir -p  /twilio-sms-api
WORKDIR  /twilio-sms-api

# Upgrade pip with no cache
RUN pip install --no-cache-dir -U pip

# Copy application requirements file to the created working directory
COPY requirements.txt .

# Install application dependencies from the requirements file
RUN pip install -r requirements.txt

# Copy every file in the source folder to the created working directory
COPY  . .

# Run the python application
CMD ["python", "main.py"]