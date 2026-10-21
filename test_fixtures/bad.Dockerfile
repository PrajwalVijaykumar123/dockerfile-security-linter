FROM ubuntu
ENV API_SECRET=supersecretvalue1234
ARG DB_PASSWORD=hunter2
RUN apt-get update && apt-get install curl git
RUN curl -sSL https://example.com/install.sh | sudo bash
ADD https://example.com/app.tar.gz /opt/app/
COPY app.py /opt/app/app.py
EXPOSE 22
EXPOSE 3306
CMD ["python3", "/opt/app/app.py"]
