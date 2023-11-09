org=ac0d3r
repo=finder

# Get all workflow runs 
echo "Delete all workflow runs!"
run_ids=( $(gh api repos/$org/$repo/actions/runs --paginate | jq '.workflow_runs[].id') )
for run_id in "${run_ids[@]}"
  do
    echo "Deleting Run ID $run_id"
    gh api repos/$org/$repo/actions/runs/$run_id -X DELETE >/dev/null
done