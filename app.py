import os
from flask import Flask, jsonify, request, render_template_string

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# --- Mock Database & Tokens ---
TOKENS = {
    "tok_merchant_a": "acct_A",
    "tok_merchant_b": "acct_BazBar"
}

# 🔒 INVOICES: Anonymized data with opaque customer references
INVOICES = {
    "inv_1001": {
        "id": "inv_1001", 
        "account_id": "acct_A", 
        "amount": 15000, 
        "currency": "usd",
        "customer_id": "cus_anon_881a", 
        "status": "paid"
    },
    "inv_2002": {
        "id": "inv_2002", 
        "account_id": "acct_B", 
        "amount": 42000, 
        "currency": "usd",
        "customer_id": "cus_anon_992b", 
        "status": "paid"
    }
}

# 🔒 SUBSCRIPTIONS: Anonymized operational metadata
SUBSCRIPTIONS = {
    "sub_1001": {
        "id": "sub_1001", 
        "account_id": "acct_A", 
        "customer_id": "cus_anon_881a",
        "plan": "enterprise_monthly", 
        "status": "active"
    },
    "sub_2002": {
        "id": "sub_2002", 
        "account_id": "acct_B", 
        "customer_id": "cus_anon_992b",
        "plan": "pro_annual", 
        "status": "active"
    }
}

# 🚨 CUSTOMERS: Holds full PII & payment metadata
CUSTOMERS = {
    "cus_anon_881a": {
        "id": "cus_anon_881a",
        "account_id": "acct_A",
        "name": "Jane Doe",
        "email": "jane@llamarama.com",
        "billing_address": "123 Llama Way, San Francisco, CA 94107",
        "payment_method": {
            "card_bin": "424242",
            "last4": "4242",
            "brand": "visa"
        }
    },
    "cus_anon_992b": {
        "id": "cus_anon_992b",
        "account_id": "acct_B",
        "name": "Alice Smith",
        "email": "alice@acme.com",
        "billing_address": "456 Enterprise Blvd, Austin, TX 78701",
        "payment_method": {
            "card_bin": "400022",
            "last4": "4242",
            "brand": "visa"
        }
    }
}

# --- Helper: Authentication Middleware ---
def authenticate_request(account_id):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False, jsonify({"error": "Missing or invalid authorization header"}), 401
    
    token = auth_header.split("Bearer ")[1].strip()
    authed_account = TOKENS.get(token)
    
    if not authed_account or authed_account != account_id:
        return False, jsonify({"error": "Unauthorized account context"}), 403
        
    return True, authed_account, 200

# --- API Endpoints ---

@app.route("/v1/merchants/<account_id>/invoices/<invoice_id>", methods=["GET"])
def get_invoice(account_id, invoice_id):
    is_valid, res, status = authenticate_request(account_id)
    if not is_valid:
        return res, status

    invoice = INVOICES.get(invoice_id)
    if not invoice:
        return jsonify({"error": "Invoice not found"}), 404

    # 🚨 VULNERABILITY (IDOR): Does not enforce invoice['account_id'] == account_id
    return jsonify(invoice), 200


@app.route("/v1/merchants/<account_id>/subscriptions/<sub_id>", methods=["GET"])
def get_subscription(account_id, sub_id):
    is_valid, res, status = authenticate_request(account_id)
    if not is_valid:
        return res, status

    subscription = SUBSCRIPTIONS.get(sub_id)
    if not subscription:
        return jsonify({"error": "Subscription not found"}), 404

    # 🛡️ SECURE: Strict boundary check prevents cross-tenant PII exposure
    if subscription["account_id"] != account_id:
        return jsonify({"error": "Access Denied: Resource boundary mismatch"}), 403

    return jsonify(subscription), 200


@app.route("/v1/merchants/<account_id>/customers/<customer_id>", methods=["GET"])
def get_customer(account_id, customer_id):
    is_valid, res, status = authenticate_request(account_id)
    if not is_valid:
        return res, status

    customer = CUSTOMERS.get(customer_id)
    if not customer:
        return jsonify({"error": "Customer not found"}), 404

    # 🚨 VULNERABILITY (IDOR Variant): Does not enforce subscription['account_id'] == account_id
    return jsonify(customer), 200


# --- Built-in Frontend Dashboard ---

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Sandbox Merchant Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #f6f9fc; color: #32325d; }
        .card { background: white; padding: 24px; border-radius: 8px; box-shadow: 0 4px 6px rgba(50,50,93,.11); margin-bottom: 20px; max-width: 800px; }
        h1 { color: #635bfc; font-size: 22px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #e6ebf1; }
        th { background-color: #f8f9fa; font-size: 12px; text-transform: uppercase; color: #8898aa; }
        .badge { background: #e3e8ee; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 12px; }
        .token-box { background: #1a1f36; color: #00d4b6; padding: 12px; border-radius: 6px; font-family: monospace; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>💳 Merchant Security Lab Dashboard</h1>
        <p>Active Account Context: <strong>acct_A (Merchant A)</strong></p>
        <div class="token-box">Authorization: Bearer tok_merchant_a</div>
    </div>

    <div class="card">
        <h3>Invoices <code>/v1/merchants/acct_A/invoices/<inv_id></code></h3>
        <table>
            <tr><th>Invoice ID</th><th>Customer Reference</th><th>Amount</th></tr>
            <tr>
                <td><span class="badge">inv_1001</span></td>
                <td><code>cus_anon_881a</code></td>
                <td>$150.00</td>
            </tr>
        </table>
    </div>

    <div class="card">
        <h3>Subscriptions <code>/v1/merchants/acct_A/subscriptions/<sub_id></code></h3>
        <table>
            <tr><th>Sub ID</th><th>Customer Reference</th><th>Plan</th></tr>
            <tr>
                <td><span class="badge">sub_1001</span></td>
                <td><code>cus_anon_881a</code></td>
                <td>Enterprise Monthly</td>
            </tr>
        </table>
    </div>

    <div class="card">
        <h3>Customers <code>/v1/merchants/acct_A/customers/<cus_id></code></h3>
        <table>
            <tr><th>Customer ID</th><th>Name</th><th>Email</th><th>Card</th></tr>
            <tr>
                <td><span class="badge">cus_anon_881a</span></td>
                <td>Jane Doe</td>
                <td>jane@llamarama.com</td>
                <td>Visa •••• 4242</td>
            </tr>
        </table>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE)


# --- AWS Lambda Handler wrapper ---
try:
    import serverless_wsgi
    def handler(event, context):
        return serverless_wsgi.handle_request(app, event, context)
except ImportError:
    pass

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)
