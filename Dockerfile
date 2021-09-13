FROM python:3

COPY requirements.txt /
RUN pip install -r requirements.txt

COPY vault_handler.py /

CMD [ "python", "./vault_handler.py" ]