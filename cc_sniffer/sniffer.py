import signal, argparse, queue, threading
from concurrent.futures import ThreadPoolExecutor
from scapy.all import AsyncSniffer, conf, IP, TCP, Raw
from .config import load_config
from .logger import setup_logger
from .metrics import pkt_counter, match_counter, error_counter, start_metrics_server
from .utils import luhn_valid, compile_patterns, timestamp, mask_cc_number
import csv

def handle_packet(raw_pkt, patterns, logger, csv_queue=None, verbose=False):
    pkt_counter.inc()
    try:
        # Early exit for non-TCP packets
        if not (IP in raw_pkt and TCP in raw_pkt and Raw in raw_pkt):
            return
            
        payload = raw_pkt[Raw].load.decode("utf-8", "ignore")
        
        # Skip packets without digits to improve performance
        if not any(char.isdigit() for char in payload):
            return
            
        for card_type, pat in patterns.items():
            for num in pat.findall(payload):
                if luhn_valid(num):
                    match_counter.inc()
                    src = f"{raw_pkt[IP].src}:{raw_pkt[TCP].sport}"
                    dst = f"{raw_pkt[IP].dst}:{raw_pkt[TCP].dport}"
                    entry = {
                        "type": card_type,
                        "number": mask_cc_number(num),  # Masked number
                        "src": src, 
                        "dst": dst,
                        "time": timestamp()
                    }
                    logger.info("card_match", extra={"extra": entry})
                    
                    if verbose:
                        print(entry)
                        
                    if csv_queue:
                        csv_queue.put([entry[k] for k in ("time","type","number","src","dst")])
                    return  # Stop after first valid match
    except Exception as e:
        error_counter.inc()
        logger.error(f"Packet processing error: {str(e)}")

def main():
    # -- load config --
    cfg = load_config()
    patterns = compile_patterns(cfg["card_types"])
    logger = setup_logger(cfg["log_path"],
                          cfg["max_log_size_mb"],
                          cfg["backup_count"])
    
    # Create CSV writer with thread-safe queue
    csv_queue = None
    csv_thread = None
    if cfg.get("csv_output"):
        csv_queue = queue.Queue()
        stop_event = threading.Event()
        
        def csv_writer_worker():
            with open(cfg["csv_output"], "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["time","type","number","src","dst"])
                while not stop_event.is_set() or not csv_queue.empty():
                    try:
                        record = csv_queue.get(timeout=1)
                        writer.writerow(record)
                    except queue.Empty:
                        continue
        
        csv_thread = threading.Thread(target=csv_writer_worker, daemon=True)
        csv_thread.start()
    
    # -- start metrics HTTP server --
    start_metrics_server(cfg["prometheus_port"])

    # -- CLI fallback for override --
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    conf.iface = cfg["interface"]
    executor = ThreadPoolExecutor(max_workers=cfg["thread_workers"])
    sniffer = AsyncSniffer(filter=cfg["bpf_filter"],
                           prn=lambda p: executor.submit(
                               handle_packet, p, patterns, logger,
                               csv_queue, args.verbose),
                           store=False)

    # graceful shutdown
    def stop(*_):
        sniffer.stop()
        if csv_thread:
            stop_event.set()
            csv_thread.join()
        executor.shutdown(wait=True)
        logger.info("sniffer_stopped")

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    logger.info("sniffer_start", extra={"extra": {"iface": cfg["interface"], "filter": cfg["bpf_filter"]}})
    sniffer.start()
    sniffer.join()

if __name__ == "__main__":
    main()
