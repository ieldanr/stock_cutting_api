#!/usr/bin/env python
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
from stock_cutting import *

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index = True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration = 600):
        s = Serializer(app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({ 'id': self.id })

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        user = User.query.get(data['id'])
        return user

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/api/users', methods = ['POST'])
@auth.login_required
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400) # missing arguments
    if User.query.filter_by(username = username).first() is not None:
        abort(400) # existing user
    user = User(username = username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({ 'username': user.username }), 201, {'Location': url_for('get_user', id = user.id, _external = True)}

@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(10000)
    return jsonify({ 'token': token.decode('ascii'), 'duration': 10000 })

@app.route('/api/solve')
@auth.login_required
def solve_stock_cutting_brute_force():
    print "Solving brute force"
    return jsonify(solve_stock_cutting(OptimalCuttingBruteForce))


@app.route('/api/solve_approx')
@auth.login_required
def solve_stock_cutting_approx():
    print "Solving approx"
    return jsonify(solve_stock_cutting(OptimalCutting))

def solve_stock_cutting(solver_class):
    args = request.args
    stock_quantities = map(lambda x: int(x), args.get('stockQuantities').split(","))
    stock_widths = map(lambda x: int(x), args.get('stockWidths').split(","))
    demand_quantities = map(lambda x: int(x), args.get('demandQuantities').split(","))
    demand_widths = map(lambda x: int(x), args.get('demandWidths').split(","))

    print stock_quantities
    print stock_widths
    print demand_quantities
    print demand_widths

    if stock_quantities is None or stock_widths is None or demand_quantities is None or demand_widths is None:
        abort(400) #missing arguments
    if len(stock_quantities) != len(stock_widths) or len(demand_quantities) != len(demand_widths):
        abort(400) #lengths wrong

    stocks = []
    for index, stock in enumerate(stock_quantities):
        stocks.append(Stock(stock_widths[index], stock))

    demands = []
    for index, demand in enumerate(demand_quantities):
        demands.append(Demand(demand_widths[index], demand))

    #stocks = [Stock(57,21)]
    #demands = [Demand(18, 35), Demand(21, 9), Demand(27,5)]
    oc = solver_class(stocks, demands)
    lp, patterns = oc.solve()
    # print 'Z = %g;' % lp.obj.value
    # print '; '.join('%s = %g' % (c.name, c.primal) for c in lp.cols)
    # print 'Status %s' % lp.status
    used = 0

    answer = []
    for i, pattern in enumerate(patterns):
        if lp.cols[i].primal >= 1:
            used += lp.cols[i].primal
            # print "stock specs:"
            # print "\tlength: %g" % pattern.stock.length
            # print "\tavailable: %g" % pattern.stock.quantity
            print "\tuse: %g" % lp.cols[i].primal
            # print '\tcuts:'
            demand_obtained = []
            for j, demand in enumerate(pattern.demands):
                if pattern.quantities[j] >= 1:
                    demand_obtained.append({
                        'width': demand.length,
                        'quantity': pattern.quantities[j]
                        })
            #     print '\t\tlength: %g, number_cuts: %g' % (demand.length, pattern.quantities[index])
            # print "\t\twaste: %g" % pattern.leftover
            answer.append({
                'width': pattern.stock.length,
                'quantity': int(lp.cols[i].primal),
                'demandObtained': demand_obtained,
                'waste': pattern.leftover
                })

    #print "Stocks used: %g" % used

    return { 'rawsUsed': answer, 'totalRawsUsed': used }

if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug = True)

