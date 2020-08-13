FROM centos/python-36-centos7

ENV WORk_SOURCE /usr/src/

ENV FLASK_ENV development

WORKDIR $WORk_SOURCE

COPY . $WORk_SOURCE

RUN pip3 install --upgrade pip || \
    python3 -m pip install --upgrade pip

RUN pip3 install \
    --trusted-host pypi.python.org \
    --trusted-host pypi.org \
    --trusted-host files.pythonhosted.org \
    -r requirements.txt

USER root

RUN yum install -y vim

EXPOSE 1990

HEALTHCHECK CMD curl --fail http://localhost:1900 || exit 1

CMD ["gunicorn", "wxbot:app", "-c", "./lib/gunicorn.conf.py"]