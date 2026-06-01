# Evolutionary scanner - learns from checkpoints and mutates strategies

import json
import os
import random
import time
from typing import List, Dict, Any

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'scan_results')
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

class EvolutionaryScanner:
    """
    Maintains a tiny population of scanning strategies and evolves them.
    This is a lightweight placeholder of a more advanced genetic/evolutionary system.
    """

    def __init__(self):
        self.generation = 0
        self.population: List[Dict[str, Any]] = [self._random_strategy() for _ in range(5)]

    def _random_strategy(self) -> Dict[str, Any]:
        return {"name": f"strat_{random.randint(1000,9999)}", "aggressiveness": random.random()}

    def observe_checkpoints(self, checkpoint_files: List[str]):
        # simplistic observation: if many ports found -> increase aggressiveness
        score = 0
        for path in checkpoint_files:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for r in data.get("results", []):
                    if r.get("type") == "port" and r.get("open"):
                        score += 1
            except Exception:
                continue

        self._evolve(score)

    def _evolve(self, score: int):
        # mutate population based on score
        self.generation += 1
        for p in self.population:
            if score > 2:
                p["aggressiveness"] = min(1.0, p["aggressiveness"] + 0.05)
            else:
                p["aggressiveness"] = max(0.0, p["aggressiveness"] - 0.02)
        self._save_model()

    def _save_model(self):
        path = os.path.join(MODEL_DIR, f"model_gen_{self.generation}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"generation": self.generation, "population": self.population}, f, indent=2)

    def best_strategy(self) -> Dict[str, Any]:
        return max(self.population, key=lambda p: p["aggressiveness"]) 

