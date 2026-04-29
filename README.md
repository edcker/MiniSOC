## 🏗️ Architecture Overview

MiniSOC follows a simple, modular pipeline:

**Log Source → Parser → Detection Engine → Alert Store → Dashboard**

- **Log Source**: Windows Security Event Logs  
- **Parser**: Extracts and structures relevant event data  
- **Detection Engine**: Applies rule-based logic (Event IDs, thresholds, and time windows)  
- **Alert Store**: Stores findings in a structured, append-only format (JSON/CSV)  
- **Dashboard**: Visualizes alerts in real time using HTML and JavaScript  

Each component is lightweight and transparent, making the system easy to understand, modify, and extend.
