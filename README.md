PYIDS is a lightweight Intrusion Detection System (NIDS) built in Python. It captures packets in real time using TShark, and sends reports to a Flask-based dashboard for visualization.

## Project Structure

PYIDS/
│
├── app.py                # Flask backend: API + dashboard routes
├── canary.py             # Packet sniffer: captures data and sends JSON reports
│
├── templates/
│   └── dash.html         # Dashboard HTML page
│
├── static/
│   └── styles.css        # Dashboard styling (modern dark UI)
│
├── reports.log           # (optional) Stored packet reports
│
└── README.md             # Project documentation

## Run

Start the Flask server:

```python app.py```


In another terminal, run the canary:

```python canary.py```


Open your browser:
http://127.0.0.1:8080
