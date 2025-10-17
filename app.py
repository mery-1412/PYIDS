from flask import Flask, request, jsonify, render_template
import logging
import json
import os

app=Flask(__name__)
logging.basicConfig(level=logging.INFO)

reports_buffer=[]

@app.route('/')
def dashboard():
    return render_template('dash.html', reports=reports_buffer)


@app.route('/api/', methods=['GET','POST'])
def api_handler():
    global reports_buffer

    if request.method=='POST':
        data=request.get_json(force=True, silent=True)
        if not data:
            return jsonify({'status': 'error', 'reason': 'no json'}), 400
        
        #append to buffer
        reports_buffer.append(data)
        app.logger.info("Received reports %s", data)
        return jsonify({'status': 'ok'}), 200

    return jsonify(reports_buffer)
    

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)