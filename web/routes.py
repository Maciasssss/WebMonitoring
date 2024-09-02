from flask import Flask, render_template, jsonify

def create_app(sniffer):
    app = Flask(__name__)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/statistics')
    def get_statistics():
        return jsonify(sniffer.get_statistics())

    return app
