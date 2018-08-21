from flask import Flask, render_template, request, redirect, url_for

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
    categories = dbSession.query(Category).all()
    return render_template('catalog.html', categories=categories)


@app.route('/catalog/<string:category_name>/')
@app.route('/catalog/<string:category_name>/items/')
def show_items(category_name):
    category = dbSession.query(Category).filter_by(
        name=category_name).one()
    items = dbSession.query(Item).filter_by(
        category_id=category.id).all()
    return render_template('items.html', category=category, items=items)


@app.route('/catalog/new/', methods=['GET', 'POST'])
def new_item():
    if request.method == 'POST':
        count = dbSession.query(Item).filter_by(
            name=request.form['name']).count()
        if count > 0:
            return redirect(url_for('new_item'))
        new_item = Item(
            name=request.form['name'],
            description=request.form['description'],
            category_id=request.form['category_id'])
        dbSession.add(new_item)
        dbSession.commit()
        category_name = dbSession.query(Category).filter_by(
            id=request.form['category_id']).one().name
        return redirect(url_for('show_item', category_name=category_name, item_name=request.form['name']))
    else:
        categories = dbSession.query(Category).all()
        return render_template('new_item.html', categories=categories)


@app.route('/catalog/<string:category_name>/<string:item_name>/')
def show_item(category_name, item_name):
    item = dbSession.query(Item).filter_by(name=item_name).one()
    return render_template('item.html', category_name=category_name, item=item)


@app.route('/catalog/<string:item_name>/edit/', methods=['GET', 'POST'])
def edit_item(item_name):
    item_to_edit = dbSession.query(Item).filter_by(name=item_name).one()
    if request.method == 'POST':
        count = dbSession.query(Item).filter_by(
            name=request.form['name']).count()
        if count > 0 and item_name != request.form['name']:
            return redirect(url_for('edit_item', item_name=item_name))
        item_to_edit.name = request.form['name']
        item_to_edit.description = request.form['description']
        item_to_edit.category_id = request.form['category_id']
        dbSession.add(item_to_edit)
        dbSession.commit()
        category_name = dbSession.query(Category).filter_by(
            id=request.form['category_id']).one().name
        return redirect(url_for('show_item', category_name=category_name, item_name=request.form['name']))
    else:
        categories = dbSession.query(Category).all()
        return render_template('edit_item.html', categories=categories, item=item_to_edit)


@app.route('/catalog/<string:item_name>/delete/')
def delete_item(item_name):
    return render_template('delete_item.html', item_name=item_name)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8080, threaded=False)
