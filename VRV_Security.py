import re
import csv
from collections import defaultdict, Counter

# Constants
LOG = 'VRV Security\sample.log'
CSV = 'VRV Security\log_analysis_results.csv'
failed = 10

def parsing(file_path):
    ip_requests = Counter()
    endpoints = Counter()
    failed_logins = defaultdict(int)

    log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"(?P<method>\w+)\s+(?P<endpoint>\/\S*)\s+\S+"\s+(?P<status>\d+)')
    failed_login_pattern = re.compile(r'401.*Invalid credentials')

    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = match.group('status')
                ip_requests[ip] += 1
                endpoints[endpoint] += 1
                if failed_login_pattern.search(line):
                    failed_logins[ip] += 1

    return ip_requests, endpoints, failed_logins

def analyze_requests(ip_requests):
    return sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

def analyze_endpoints(endpoints):
    return endpoints.most_common(1)[0] if endpoints else None

def detect_suspicious_activity(failed_logins, threshold):
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP requests
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)
        writer.writerow([])

        # Write most accessed endpoint
        writer.writerow(["Most Frequently Accessed Endpoint"])
        if most_accessed_endpoint:
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])

        # Write suspicious activity
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity.items())


ip_requests, endpoints, failed_logins = parsing(LOG)

# Analyze data
sorted_requests = analyze_requests(ip_requests)
most_accessed_endpoint = analyze_endpoints(endpoints)
suspicious_ips = detect_suspicious_activity(failed_logins, failed)

# Display results
print("Requests per IP Address:")
for ip, count in sorted_requests:
    print(f"{ip:20} {count}")

if most_accessed_endpoint:
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

if suspicious_ips:
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:20} {count}")

save_to_csv(sorted_requests, most_accessed_endpoint, suspicious_ips, CSV)
print(f"\nResults saved to {CSV}")
