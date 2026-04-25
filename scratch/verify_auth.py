import requests

BASE_URL = "http://127.0.0.1:8000"

def test_auth():
    # 1. Test Register
    reg_data = {"username": "test_op_99", "password": "password123"}
    try:
        r = requests.post(f"{BASE_URL}/register", data=reg_data)
        print(f"Register Response: {r.status_code}, {r.json()}")
        
        # 2. Test Login
        login_data = {"username": "test_op_99", "password": "password123"}
        r = requests.post(f"{BASE_URL}/login", data=login_data)
        print(f"Login Response: {r.status_code}, {r.json()}")
        
        if r.status_code == 200:
            token = r.json().get("access_token")
            print("Login Success!")
            return token
    except Exception as e:
        print(f"Error during verification: {e}")
    return None

if __name__ == '__main__':
    test_auth()
