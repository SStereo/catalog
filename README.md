Catalog App
=============

This Project was created by SStereo to learn python/html/CSS during the Udacity
Nanodegree Training. Feel free to use this code for your own training purposes.

INSTALL & RUN
--------------------
1. Download/Clone the repository onto your local hard drive
2. Install Udacity vagrant vm (https://github.com/udacity/fullstack-nanodegree-vm)
3. Start the vagrant vm using vagrant up and connect via ssh
4. Install additional required libraries using pip install: flask-sqlalchemy
5. Change to the directory /vagrant/catalog
6. In the file application.py set the facebook and google client id and
   secret keys at the global constants GOOGLE_WEB_CLIENT_ID,
   GOOGLE_CLIENT_SECRET, FACEBOOK_APP_ID and FACEBOOK_SECRET_KEY
7. Enter commmand 'python application.py' to start the application
8. The sqlite database is automatically generated after the first request with
   some sample data

FEATURES
--------
1. Browse categories with items
2. Create, modify and delete items
3. Upload an image for items
4. Authenticate via Google, Facebook or with your email
5. Responsive design supporting mobile devices
6. Material design based on bootstrap front end libraries
7. Cross-Site Request Forgery protection using csrf token in CRUD operations

CONTACT
-------
You can contact me on GitHub under SStereo.
