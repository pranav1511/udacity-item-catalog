# Item Catalog
A simple python based web application which provides a list of items within a variety of categories and implements third party Authentication and Authorization like Google and Facebook.


## Getting Started

### Requirements
* [VirtualBox](https://www.virtualbox.org/)
* [Vagrant](https://www.vagrantup.com/)
* [Udacity Vagrant File](https://github.com/udacity/fullstack-nanodegree-vm)

### Setup
* Run the Vagrant Machine and access ssh `vagrant up` `vagrant ssh`
* Move inside the project folder `cd /vagrant/catalog`
* Setup the database `python database_setup.py`
* Populate database with Categories `python populate_categories.py`

### Launch
* Run the Application `python application.py`
* The application can be accessed at http://localhost:8080
* The JSON format of the items in the catalog can be accessed from http://localhost:8080/catalog/JSON
* The JSON format of an item in the catalog can be accessed from http://localhost:8080/item/{item_name}/JSON (Replace {item_item} with the item you want)
* The JSON format of the categories in the catalog can be accessed from http://localhost:8080/categories/JSON


## Known Issues
* Limited validation in form data


## Skills Used
* HTML
* CSS
* Javascript
* JSON
* Bootstrap
* Python
* Flask
* Jinja2
* SQLAlchemy
* RESTful APIs
* OAuth2 (Google and Facebook login)


# License
Item Catalog is licensed under the [MIT License](https://github.com/pranav1511/udacity-item-catalog/blob/master/LICENSE.txt).