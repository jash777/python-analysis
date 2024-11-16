from transformers import AutoModelForCausalLM, AutoTokenizer

model_name = "tiiuae/falcon-7b-instruct"  # Replace with "falcon-40b" if needed
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name, device_map="auto", trust_remote_code=True)
