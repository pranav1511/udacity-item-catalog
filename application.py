from flask import Flask, render_template, request, redirect, url_for

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

GOOGLE_CLIENT_ID = json.loads(
    open('google_client_secrets.json', 'r').read())['web']['client_id']

FACEBOOK_APP_ID = json.loads(
    open('facebook_client_secrets.json', 'r').read())['web']['app_id']

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


@app.route('/catalog/<string:item_name>/delete/', methods=['GET', 'POST'])
def delete_item(item_name):
    item_to_delete = dbSession.query(Item).filter_by(name=item_name).one()
    if request.method == 'POST':
        dbSession.delete(item_to_delete)
        dbSession.commit()
        category_name = dbSession.query(Category).filter_by(
            id=item_to_delete.category_id).one().name
        return redirect(url_for('show_items', category_name=category_name))
    else:
        return render_template('delete_item.html', item=item_to_delete)


@app.route('/login/')
def show_login():
    state = '' . join(random.choice(string.ascii_uppercase +
                                    string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', state=state, GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID, FACEBOOK_APP_ID=FACEBOOK_APP_ID)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(
            'google_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != GOOGLE_CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    response_json = {}
    response_json['username'] = login_session['username']
    response_json['picture'] = login_session['picture']
    response_json['email'] = login_session['email']
    response = make_response(json.dumps(response_json), 200)
    response.headers['Content-Type'] = 'application/json'
    print('done')
    return response


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s' % access_token)
    print('User name is: ')
    print(login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


if __name__ == '__main__':
    app.secret_key = 'perfect_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8080, threaded=False)
