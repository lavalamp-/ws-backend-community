# Web Sight Back-end (API & Task Node)

[![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/2017.svg)](https://www.toolswatch.org/2017/06/the-black-hat-arsenal-usa-2017-phenomenal-line-up-announced/)

Web Sight is a software platform that enables red and blue teams to automate the information gathering processes required by their day-to-day jobs. At present, Web Sight performs the following activities:

* Domain name enumeration
* DNS record enumeration
* Network scanning (large scale)
* Network service fingerprinting
* SSL support enumeration
* SSL certificate inspection
* Application-layer inspection for supported application protocols (currently only HTTP)

These activities are entirely automated, and require only the following information as scanning "seeds":

* Network ranges
* Domain names

For web applications that are discovered across an organization's domain names and network ranges, the following activities are conducted:

* Virtual host enumeration
* User agent enumeration
* Crawling
* Screen shotting

The goal of automating this information gathering process is to provide users with the situational awareness that proper security strategizing (both offensively and defensively) requires. Simply put, how can you hope to attack and/or defend an organization if you don't have a good understanding of the organization's attack surface at a given point in time? Furthermore, given the nature of enterprise attack surface (constant churn, massive scale), any understanding of attack surface is fleeting, and attack surface must be re-evaluated regularly to maintain situational awareness.

Please note that this documentation is very much a work in progress. If you find any part of it confusing, please feel free to submit a question via GitHub and I will do my best to respond in a timely fashion.

## Introduction

This repository contains the code used by all of the Web Sight back-end components. In terms of the n-tier deployment of the Web Sight platform, this repository contains the code for:

* The REST API
* Task nodes

For the REST API, Web Sight makes use of [Django Rest Framework](http://www.django-rest-framework.org/). Running the REST API follows standard Django functionality.

For the task nodes, Web Sight makes use of [Celery](http://www.celeryproject.org/) (with heavy reliance upon Celery's [Canvas](http://docs.celeryproject.org/en/latest/userguide/canvas.html) functionality).

## Dependencies

At a high level, the Web Sight back-end relies upon the following technologies:

* [Celery](http://www.celeryproject.org/) - Distributed task processing and management
* [Celery Flower](http://flower.readthedocs.io/en/latest/) - Monitoring of tasks
* [Django Rest Framework](http://www.django-rest-framework.org/) - API functionality
* [SQLAlchemy](https://www.sqlalchemy.org/) - ORM functionality
* [Aldjemy](https://pypi.python.org/pypi/aldjemy/0.7.0) - Enabling tasks to query database content using SQLAlchemy syntax (fine query granularity control)
* [Elasticsearch](https://www.elastic.co/) - Data collected by task nodes is largely stored in Elasticsearch to enable rapid querying and insertion at scale as well as to reduce database load
* [Redis](https://redis.io/) - Caching of function call return values and storage of Celery task results
* [RabbitMQ](https://www.rabbitmq.com/) - AMQP server for managing task queue(s)
* [Nmap](https://nmap.org/) - Scanning multiple ports on a single host
* [Zmap](https://zmap.io/) - Scanning a single port across a large number of hosts
* [PhantomJS](http://phantomjs.org/) - Taking screenshots of web applications
* [AWS S3](https://aws.amazon.com/s3/) - File storage
* [PostgreSQL](https://www.postgresql.org/) - Web Sight makes use of PostgreSQL for storage of all database-related data

## Directory Layout

The contents of the Web Sight back-end project are laid out as follows. Some areas of the codebase are not listed here as their purposes should be somewhat self-evident:

```
/files/ - Assorted files that are used by various components
/lib/ - General platform library
/lib/export/ - Exporting data to various file types
/lib/fingerprinting/ - Fingerprinting network services
/lib/inspection/ - Gathering data about sources of interest (network services, domain names, etc.) as well as collating gathered data into reports
/lib/parsing/ - Parsing various types of data
/lib/smtp/ - All things email
/lib/sqlalchemy/ - Querying the database using SQLAlchemy syntax on top of Django models
/lib/tools/ - Wrapper classes for invoking third-party tools
/lib/wscache/ - Caching data
/rest/ - Django Rest Framework API code
/rest/lib/ - General code used only be REST API
/rest/views/elasticsearch/ - Django handlers that query Elasticsearch based on database model data
/tasknode/ - All code for tasks used by the Web Sight task nodes
/tests/ - Unit tests (note that directory structure within this directory mirrors structure of Web Sight project)
/wsbackend/ - Configuration for the REST API
/wselasticsearch/ - Custom wrapper library for interacting with Elasticsearch
/wselasticsearch/flags/ - Flagging data stored in Elasticsearch based on filters and search terms
/wselasticsearch/models/ - Elasticsearch document models along with functionality that maps documents to database model instances
/wselasticsearch/ops/ - Individual functions that query Elasticsearch and return python basic data types
/wselasticsearch/query/ - Query classes that wrap Elasticsearch querying functionality and provide additional structure for querying the document models used by Web Sight
```

## Installation

**Web Sight has been tested and works with both OSX and Ubuntu. The steps here should work on other Linux distributions, but YMMV.**

To get started with the Web Sight back-end, first clone the repository and `cd` into the cloned directory:

```
git clone https://github.com/lavalamp-/ws-backend-community.git
cd ws-backend-community
```

Once in the cloned directory, you may want to [create and activate a virtual environment](http://python-guide-pt-br.readthedocs.io/en/latest/dev/virtualenvs/) (if using venv is your sort of deal). Virtual environment or no, the next step is to install the Python dependencies using [pip](https://pypi.python.org/pypi/pip):

```
pip install -r requirements.txt
```

With the Python dependencies installed, we now must install all of the other third-party software that the Web Sight back-end requires. Note that the installation process for these dependencies can vary greatly depending on what platform you are using, so I'll leave links here to the technologies and their respective installation instructions:

* [PostgreSQL](https://www.postgresql.org/download/)
* [Elasticsearch 5.*](https://www.elastic.co/guide/en/elasticsearch/reference/current/_installation.html)
* [Redis](https://redis.io/topics/quickstart)
* [RabbitMQ](https://www.rabbitmq.com/download.html) (you will probably want to install RabbitMQ with the [management console enabled](https://www.rabbitmq.com/management.html))
* [PhantomJS](http://phantomjs.org/download.html)
* [Nmap](https://nmap.org/book/install.html)
* [Zmap](https://github.com/zmap/zmap)

Once all of these dependencies have been installed, you will want to:

1. Create a [database user as well as a database within PostgreSQL](https://www.ntchosting.com/encyclopedia/databases/postgresql/create-user/)
2. Give [full permissions for the given database user on the newly-created database](https://www.postgresql.org/docs/9.0/static/user-manag.html)
3. Ensure that the given PostgreSQL user can [access the database server from the IP address(es) where you'll be running Web Sight from](https://www.postgresql.org/docs/9.1/static/auth-pg-hba-conf.html)
4. Create [a user and a virtual host within RabbitMQ](https://www.rabbitmq.com/man/rabbitmqctl.1.man.html)
5. Give full permissions for the given virtual host to the given user within [RabbitMQ](https://www.rabbitmq.com/man/rabbitmqctl.1.man.html)
6. Create a [user within Elasticsearch](https://www.elastic.co/guide/en/x-pack/current/setting-up-authentication.html)

With all of the Python-based and third-party dependencies now installed, we can move on to configuration and setup.

## Configuration & Setup

Web Sight makes use of multiple third-party services to provide various parts of its functionality. Full configuration and setup should include registering for these services:

* [Amazon Web Services](https://aws.amazon.com/) (**req'd**) - Usage of S3 (**req'd**) and usage of Amazon Elasticsearch (optional)
* [Farsight DNSDB](https://www.dnsdb.info/) (optional) - Greatly boosts domain name enumeration
* SMTP Mail Server (**req'd**) - Sending emails, can be any SMTP service
* [reCAPTCHA](https://www.google.com/recaptcha/intro/invisible.html) (**req'd**) - Protects against automated attacks, will be phased out soon

Once you have registered for these third-party services, copy the example task node configuration file to the expected configuration file location:

```
cp tasknode/tasknode.cfg.example tasknode/tasknode.cfg
```

We shall now add the necessary values to this configuration file. Note that many of the configuration values in the `tasknode.cfg` file are not listed here - the only ones listed here are the ones that are required to be modified before Web Sight will run for you. At present the `tasknode.cfg` file is not documented, but brief explanations of the various configuration values can be found in the `lib.ConfigManager` class.

The fields you must update in the `tasknode.cfg` file are as follows:

```
[AWS]

aws_key_id - Your AWS key ID
aws_secret_key - Your AWS secret key

[Celery]

celery_user - Your RabbitMQ user
celery_pass - Your RabbitMQ password
celery_host - The hostname (or IP address) where the RabbitMQ server is running
celery_virtual_host - The name of the virtual host that you added to RabbitMQ

[Database]

db_host - The IP address or hostname where your PostgreSQL server is running
db_port - The port where your PostgreSQL server is running
db_name - The name of the database to use for Web Sight
db_user - The username to connect to PostgreSQL with
db_password - The password to connect to PostgreSQL with

[DNS]

dns_hosts_file_location - The local file path to where the system hosts file is located
dns_dnsdb_api_key - Your Farsight DNSDB API key

[Elasticsearch]

es_username - The username to connect to Elasticsearch with
es_password - The password to connect to Elasticsearch with
es_host - The hostname or IP address where your Elasticsearch server is running
es_port - The port where your Elasticsearch server is running
es_use_aws - Whether or not to use AWS Elasticsearch (if you set this value to True, then the credentials in the [AWS] section will be used to connect to AWS and the other connection values within [Elasticsearch] will be ignored.

[Recaptcha]

recaptcha_secret - Your reCAPTCHA secret key

[Redis]

redis_host - The hostname or IP address where your Redis server is running
redis_port - The port where your Redis server is running

[Rest]

rest_domain - The URL where your REST API will be running

[SMTP]

smtp_username - The username to connect to your SMTP server with
smtp_password - The password to connect to your SMTP server with
smtp_host - The hostname or IP address where your SMTP server is running
smtp_port - The port where your SMTP server is running

```

Once the values above have been updated in the `tasknode.cfg` file, the Web Sight task node should be properly configured. Next, we must configure the REST API.

First, copy the example Django settings file to the expected configuration file path:

```
cp wsbackend/settings.py.example wsbackend/settings.py
```

The example `settings.py` file contains blocks surrounded by square brackets (`[[EXAMPLE]]`) for all of the places where you must update the configuration file. The values should be updated as follows:

```
[[DJANGO_SECRET]] - A large, unguessable random string
[[ALLOWED_HOSTS_LIST]] - A list of strings depicting all of the hostnames that the REST API will be served under
[[DB_NAME]] - The name of the database that Web Sight will use
[[DB_USER]] - The user to connect to the database with
[[DB_PASSWORD]] - The password to connect to the database with
[[DB_HOST]] - The hostname or IP address where the database resides
[[DB_PORT]] - The port where the database resides
[[CORS_ORIGINS]] - A list of strings representing all of the domains from which cross-origin requests should be accepted (ie: where your Web Sight front-end deployment is served from)
[[SMTP_HOST]] - The hostname or IP address where your SMTP server resides
[[SMTP_PORT]] - The port where your SMTP server resides
[[SMTP_USER]] - The user to connect to your SMTP server with
[[SMTP_PASSWORD]] - The password to connect to your SMTP server with
[[SMTP_USE_TLS]] - A boolean value depicting whether or not to connect to your SMTP server using SSL/TLS.
```

With the third-party integrations set up and the `tasknode.cfg` and `settings.py` files fully-configured, we can now bootstrap the database. Run the following commands from the root Web Sight back-end directory:

```
python manage.py makemigrations rest
python manage.py migrate
```

With the database now bootstrapped, we can create our first user. This user will be configured as an administrative user:

```
python manage.py createsuperuser
```

We now must activate the user so that we can authenticate with the account. Replace the <email> string below with the email address of the user that you created:

```
python manage.py shell -c "from rest.models import WsUser; user = WsUser.objects.get(email='<email>'); user.is_active = True; user.email_verified = True; user.save()"
```

We now must complete some final housekeeping for bootstrapping some of the configuration values stored within the database as well as the default Elasticsearch index:

```
python -c "from wselasticsearch import update_model_mappings, create_user_info_index; from lib.bootstrap import bootstrap_order_tiers, bootstrap_zmap_configs, bootstrap_nmap_configs; update_model_mappings(); create_user_info_index(); bootstrap_order_tiers(); bootstrap_zmap_configs(); bootstrap_nmap_configs();"
```

And with that, we have now set up all of Web Sight's back-end dependencies and have bootstrapped the various data stores used by Web Sight with default configuration values. We can now move on to testing that the deployment is configured correctly.

## Testing

As you may have noticed, getting Web Sight's back-end properly configured and running is a huge pain (although we believe the pain is well worth it). In order to check and make sure that the third-party dependencies are properly configured and that the database is bootstrapped with the necessary values, run the following from the root Web Sight back-end directory:

```
python -c "from lib.deploy import DeployChecker; x = DeployChecker(); x.print_status();"
```

You will see a list of checklist items as well as some boolean values that depict (1) whether a connection can be made to the given service and (2) whether authentication to the given service was successful. As of the time of writing this, one row ("Chris Account") should return False. This is not a problem, as it is doing a check for whether or not my personal account is present. So long as you have already added an administrative user, you can ignore this value being False.

If the `DeployChecker.print_status()` results above indicate that all systems are go, run the following to check that all unit tests are currently passing:

```
python manage.py test
```

If all of the unit tests pass, then you are good to go with running the API server as well as the task node. Note that at the time of writing, `TestWebScanInspector` is failing two tests. You can ignore these test failures.

If you would like to check for unit test coverage, you can run the following:

```
coverage run --source='.' manage.py test
```

## Running the API Server

The Web Sight REST API can be run using standard Django Rest Framework commands:

```
python manage.py runserver
```

## Running a Task Node

A Web Sight Celery task node can be run using standard Celery commands. Note that at the time of writing, the task node must be run with `root` privileges as required by `Zmap` and UDP `nmap` scans. We know that this is not a good thing, and invite anyone that has a good solution other than sandboxing the task node to submit a pull request!

```
celery worker -A tasknode -l info
```

## Monitoring Task Nodes

To monitor the status of tasks that have been received by Web Sight task nodes, we rely upon the Celery Flower package. To run the Flower web server, invoke the following command from the root Web Sight directory:

```
flower -A tasknode --port=5555
```

The Flower web server can then be accessed via localhost at the chosen port (port 5555 in the example above).

## Documentation

**THE CODE IS SO GOOD THAT IT'S PRACTICALLY SELF-DOCUMENTING.**

Loljk that's not true at all. Right now I'm an army of one and I don't have any centralized documentation to offer. I'd love for a community to grow around this project and aid in the development of project documentation. Either way though, I intend to have a wiki / readthedocs project put together at some point in the future.

I have made a concerted effort to document every class, method, and function. That being said, I am sure that plenty of the documentation doesn't make sense.

## Contributing

Yes. Please. Please contribute. At the time of writing this, the majority of code has been written by yours truly, with some fantastic aid from my partner in crime Iggy Krajci.

If you would like to contribute please first take a thorough tour of the codebase and try to get a good understanding of the layout and coding paradigms that are in play. Once you have some amount of an understanding fire away as many pull requests as you so please!

I will hopefully have a contributing guide up alongside the aforementioned documentation at some point in the future. Until then, please feel free to ask as many questions as you like to clarify any understanding that you strive to have. I will also have a requested feature list either on GitHub or Trello - again the only constraint is my only having two hands and 24 hours of time in a day.

## Questions

I'm a big fan of Metasploit's approach to asking questions - "Don't ask to ask, just ask." I will happily answer your questions to the best of my ability permitting I am not super swamped with other things. Questions can be asked via any of the following (in descending order of preference):

* GitHub - [open issue](https://github.com/lavalamp-/ws-backend-community/issues)
* IRC - #thedeepestweb on [Freenode](https://freenode.net/), username is lavalamp
* Twitter - [@_lavalamp](https://twitter.com/@_lavalamp)
* Email - chris AT websight DOT io
