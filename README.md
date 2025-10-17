PYIDS is a lightweight Intrusion Detection System (NIDS) built in Python. It captures packets in real time using TShark, and sends reports to a Flask-based dashboard for visualization.

## Project Structure

pyids/
├── canary.py          # Main script running packet sniffing and sending reports
├── app.py             # Flask backend with API and dashboard
├── templates/
│   └── dash.html      # Dashboard UI
└── static/
    └── styles.css     # Dashboard styling

## Run

Start the Flask server:

```python app.py```


In another terminal, run the canary:

```python canary.py```


Open your browser:
http://127.0.0.1:8080