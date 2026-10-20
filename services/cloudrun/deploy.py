"""Deploy an already provisioned bucket, service identity and reviewed image."""
import argparse
import subprocess


def main():
    parser=argparse.ArgumentParser()
    for option in ["project","region","service","bucket","service-account","image","audience"]:
        parser.add_argument("--"+option,required=True)
    args=parser.parse_args()
    if "@sha256:" not in args.image:
        raise SystemExit("Deploy a reviewed immutable image digest.")
    command=["gcloud","run","deploy",args.service,"--project="+args.project,"--region="+args.region,
             "--platform=managed","--image="+args.image,"--service-account="+args.service_account,
             "--cpu=2","--memory=4Gi","--no-cpu-throttling","--scaling=1",
             "--max-instances=1","--concurrency=8","--timeout=120","--allow-unauthenticated",
             "--set-env-vars=WIPSTASH_BUCKET="+args.bucket+",WIPSTASH_AUDIENCE="+args.audience,
             "--startup-probe=httpGet.path=/health,httpGet.port=8080,periodSeconds=10,timeoutSeconds=5,failureThreshold=24",
             "--liveness-probe=httpGet.path=/health,httpGet.port=8080,periodSeconds=10,timeoutSeconds=5,failureThreshold=3"]
    subprocess.run(command,check=True)


if __name__=="__main__":
    main()
