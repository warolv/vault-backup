FROM python:3.10.0b4

COPY requirements.txt /
RUN pip install -r requirements.txt

COPY vault_handler.py /

CMD [ "python", "./vault_handler.py" ]