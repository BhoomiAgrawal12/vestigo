import frida
import logging
import os

class Instrumentation:
    def __init__(self, process_id_or_name):
        self.target = process_id_or_name
        self.session = None
        self.script = None
        self.logger = logging.getLogger("Instrumentation")

    def generate_hooks_script(self, findings):
        """
        Generates the final Frida script by injecting hooks into the template.
        
        findings: A dictionary containing 'openssl_symbols' (list) or 'custom_crypto' (list of dicts).
        """
        template_path = os.path.join(os.path.dirname(__file__), 'hooks_template.js')
        with open(template_path, 'r') as f:
            template = f.read()

        hooks_code = ""

        # Scenario A: OpenSSL Hooks
        if 'openssl_symbols' in findings:
            for symbol in findings['openssl_symbols']:
                # We assume these are function names resolved by Frida's Module.findExportByName if not absolute addresses
                # But for simplicity in this template, let's assume we might need to resolve them or they are addresses.
                # If they are names:
                hooks_code += f"""
var {symbol}_ptr = Module.findExportByName(null, "{symbol}");
if ({symbol}_ptr) {{
    Interceptor.attach({symbol}_ptr, {{
        onEnter: function(args) {{
            console.log("[+] Hit {symbol}");
            // Custom logic for specific OpenSSL functions could go here
            // For now, just dump first 2 args
            logSecret("openssl_call", "{symbol}", {{
                arg0: args[0],
                arg1: args[1]
            }});
        }}
    }});
}} else {{
    console.log("[-] Could not find export {symbol}");
}}
"""

        # Scenario B: Custom Crypto (Address based)
        if 'custom_crypto' in findings:
            for item in findings['custom_crypto']:
                addr = item.get('address')
                if addr:
                    hooks_code += f"""
Interceptor.attach(ptr("{addr}"), {{
    onEnter: function(args) {{
        console.log("[+] Hit Custom Crypto at {addr}");
        logSecret("custom_crypto", "{addr}", {{
            context: this.context
        }});
    }}
}});
"""

        final_script = template.replace("// {{DYNAMIC_HOOKS}}", hooks_code)
        return final_script

    def attach_and_inject(self, findings):
        """Attaches to the process and injects the generated script."""
        try:
            self.session = frida.attach(self.target)
            self.logger.info(f"Attached to process {self.target}")

            script_code = self.generate_hooks_script(findings)
            self.script = self.session.create_script(script_code)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    if payload.get('type') == 'secret':
                        self.logger.info(f"SECRET CAPTURED: {payload}")
                        with open("secrets.log", "a") as f:
                            f.write(f"{payload}\n")
                else:
                    self.logger.debug(f"Frida Message: {message}")

            self.script.on('message', on_message)
            self.script.load()
            self.logger.info("Script loaded successfully.")

        except Exception as e:
            self.logger.error(f"Failed to attach or inject: {e}")
            raise

    def detach(self):
        if self.session:
            self.session.detach()
            self.logger.info("Detached from process.")
