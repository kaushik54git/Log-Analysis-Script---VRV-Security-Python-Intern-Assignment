### Log Analysis Script for VRV Security

This project is a Python script built for analyzing server logs, created as part of the VRV Security Python Intern Assignment. The script processes log files to extract key insights, helping to monitor system activity and detect potential security threats.

#### **Features**
1. **Request Counts by IP**  
   - Counts how many requests each IP address made.  
   - Displays the results sorted by request frequency.

2. **Most Accessed Endpoint**  
   - Identifies the endpoint that users access the most.  

3. **Suspicious Activity Detection**  
   - Flags IPs with excessive failed login attempts (e.g., HTTP `401` status).  
   - Customizable threshold for flexibility.

4. **Easy Output**  
   - Clear results shown in the terminal and saved in a CSV file for later review.
