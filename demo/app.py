from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello World!'

@app.route('/demo')
def demo():
    code = request.args.get('id')
    html = "<h3>hello, %s</h3>"%(code)
    return render_template_string(html)

if __name__ == '__main__':
    app.run()
