# DoSGuard: DoS detection and management system

React + Vite dashboard over a FastAPI backend. **Defensive simulation:** synthetic one-second traffic windows (normal, flash crowd, SYN / UDP / HTTP flood) are scored by a statistical alarm plus a Random Forest; confirmed attacks get graduated mitigation (rate limit, then temporary block, auto-expiry, allow-list). It generates no real network traffic and never touches a firewall.

```
dosguard/
├── package.json  vite.config.js  requirements.txt  pytest.ini
├── backend/app/   simulator.py  detector.py  mitigation.py  engine.py  main.py
├── backend/tests/ test_system.py
└── frontend/src/  App.jsx  api.js  components/ (Timeline, Mitigations, EventLog, Evaluation)
```

## Setup and run
```bash
npm install && pip install -r requirements.txt
npm run dev:all      # http://localhost:5173 (API docs at :8000/docs)
npm start            # build + serve everything on :8000
npm run test:api     # 9 backend tests
```

## How it works
1. `simulator.py` makes a window of per-source packet counts, then 7 features (packets/s, unique sources, source entropy, top-source share, median per-source rate, SYN ratio, mean size).
2. `detector.py`: quick statistical alarm (rate spike, dominant source, SYN-heavy) and a Random Forest labelling normal / syn / udp / http flood with an attack probability.
3. `engine.py`: act if attack probability >= 0.7, or the alarm lasts 2 windows and the model is at least unsure (>= 0.3). Offenders are sources above 15 packets/s; with none (spoofed SYN flood) a global filter is advised.
4. `mitigation.py`: first offence rate-limits (5 windows), repeat offence blocks (20 windows), allow-listed sources are never touched, everything expires on its own.

## Honest limits
Data and attacks are synthetic and separable by construction, so the in-app evaluation shows the pipeline works, not real-world accuracy. For that, replace `simulator.py` with flow features from CICIDS2017 / CIC-DDoS2019 and retrain. Thresholds are illustrative. State is in memory (single session).
