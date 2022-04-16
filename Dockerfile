FROM python:3


WORKDIR /usr/src/mlops


COPY req.txt ./


RUN pip install --upgrade pip 


RUN pip install --no-cache-dir -r req.txt


COPY . .


CMD [ "python", "./fate6.py" ]