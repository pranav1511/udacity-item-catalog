from flask import Flask, render_template

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
dbSession = DBSession()


@app.route('/')
@app.route('/catalog/')
def show_catalog():
    return render_template('catalog.html')


@app.route('/catalog/<string:category_name>/')
@app.route('/catalog/<string:category_name>/items/')
def show_items(category_name):
    return render_template('items.html', category_name=category_name)


@app.route('/catalog/new/')
def new_item():
    return render_template('new_item.html')


@app.route('/catalog/<string:category_name>/<string:item_name>/')
def show_item(category_name, item_name):
    return render_template('item.html', category_name=category_name, item_name=item_name)


@app.route('/catalog/<string:item_name>/edit/')
def edit_item(item_name):
    return render_template('edit_item.html', item_name=item_name)


@app.route('/catalog/<string:item_name>/delete/')
def delete_item(item_name):
    return render_template('delete_item.html', item_name=item_name)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
