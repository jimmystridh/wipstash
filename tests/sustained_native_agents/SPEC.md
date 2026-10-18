# Frozen sustained native-agent expense-ledger contract v1

Public API: summarize(rows, budgets=None) -> dict. rows may be a generator and is materialized once. Rows are mappings. Baseline keys count and total must always remain. Each feature is one independent implementation/publication wave. Agents may not implement future waves early. Each feature must edit shared report.py/summarize and add meaningful tests. No policy checks are configured; semantic correctness is assessed separately.

Shared semantics (provided in baseline helpers): amount(row) = Decimal(str(row.get('amount') or 0)); inputs are finite numeric strings/numbers, missing/null amounts mean zero. Money and percentage outputs: accumulate exact Decimal, round only final result to two decimals using ROUND_HALF_UP, convert to float, normalize negative zero to 0.0. mean/median likewise money. text(row,key,default) = stripped str of non-null values, using default for missing/null/blank. Category default 'uncategorized', currency default 'USD' (no case conversion), merchant/payment default 'unknown'. Dates: only canonical valid YYYY-MM-DD strings count; other nonempty values invalid; missing/null/blank dates are undated. Flags are enabled only by literal boolean True. List indexes are zero-based input positions. Sorted maps use lexicographic keys. No FX conversion: cross-currency global amounts are numerical aggregates only.

Actor A: expense behavior
A1 cash_flow = {spending: sum of positive amounts, refunds: absolute sum of negative amounts, net: signed sum}.
A2 amount_stats = {min,max,mean,median} across all signed amounts, including zero/missing. All four 0.0 when empty. Even median averages two central exact values before rounding.
A3 largest_expenses = up to three {index,amount,merchant} records for positive amounts, sorted descending exact amount then ascending original index. merchant uses fallback unknown.
A4 spend_bands = counts {refund,zero,small,medium,large}; refund <0, zero ==0, small 0<a<10, medium 10<=a<100, large a>=100.
A5 reimbursement = {eligible,paid,outstanding}; consider positive rows with reimbursable is True; eligible sum all, paid subset reimbursed is True, outstanding remainder.
A6 recurring = {count,total}; rows recurring is True, signed amounts including zero/refunds; count matching rows, total signed sum.
A7 merchant_totals = map merchant -> signed rounded total, including merchants represented only by zero rows.
A8 payment_methods = map payment_method -> {count,total}; fallback unknown, count rows and signed rounded total.

Actor B: classification and budgets
B1 by_category = map category -> signed rounded total.
B2 category_stats = map category -> {count,spending,refunds,net}; spending positive, refunds absolute negative, net signed.
B3 category_leader = category with greatest gross positive spending (tie lexicographic), or null if no positive spending. Categories with only refunds/zeros cannot win.
B4 category_shares = map every represented category -> its percentage of total gross positive spending, rounded half-up; all 0.0 if denominator zero.
B5 budgets = map budget category -> {budget,spent,remaining,over}; budgets argument is optional mapping of category string to finite nonnegative numeric budget. Only supplied keys appear, sorted. spent is gross positive spending in category; remaining = budget - spent (may be negative); over = max(spent - budget,0). Compare and subtract exact amounts before rounding. None means empty mapping.
B6 currency_totals = map currency -> signed rounded total.
B7 currency_category = map currency -> map category -> signed rounded total.
B8 uncategorized = {count,total,indexes}; rows with missing/null/blank category, or explicit stripped category equal to 'uncategorized'. Signed total, indexes input order.

Actor C: calendar analytics
C1 date_range = {start,end} earliest/latest valid date strings, or null if no valid date.
C2 by_month = map YYYY-MM -> signed rounded total for valid dates.
C3 by_day = map YYYY-MM-DD -> signed rounded total for valid dates.
C4 monthly_flow = map YYYY-MM -> {spending,refunds,net} for valid dates.
C5 activity = {active_days,dated_rows,undated_rows}; valid unique dates, count valid dated rows, remainder (including malformed dates).
C6 weekend = {count,spending,net}; rows dated Saturday/Sunday; positive spending and signed net.
C7 daily_average = gross positive spending on valid dated rows divided by number of distinct valid dates, or 0.0 if no valid date. Refund-only/zero days count in denominator.
C8 longest_streak = {days,start,end}; longest consecutive run of distinct valid dates, ties earliest start; empty => {days:0,start:null,end:null}.

Actor D: audit and tax
D1 taxes = {total,net_before_tax}; tax amount is Decimal(str(row.get('tax') or 0)); missing/null=zero, signed finite numeric. total=sum taxes on all rows, net_before_tax=sum amounts - sum taxes, rounding only final results.
D2 deductible = {count,spending,tax}; rows deductible is True AND amount>0; count, positive amount sum, corresponding signed tax sum.
D3 receipts = {required,missing,indexes}; required rows amount>=25, missing those whose receipt text is absent/null/blank. indexes missing required rows in input order.
D4 duplicate_ids = map nonempty stripped id -> count for IDs appearing more than once, sorted. Missing/null/blank ids ignored; all row signs count.
D5 data_quality = {missing_amount,invalid_dates,missing_category,missing_currency}; missing_amount means key absent or value null (zero and empty string are not missing); invalid_dates means nonempty stripped date not canonical valid date; missing category/currency means missing/null/blank, explicit fallback words do not count missing.
D6 refund_links = {matched,unmatched,total_matched}; inspect negative rows. A refund matches if its nonempty stripped original_id equals nonempty stripped id on any positive row in the entire input, independent of ordering. matched/unmatched are counts; total_matched absolute summed matched refund amounts. No cap by original amount; duplicates do not multiply matches.
D7 review_flags = list {index,reasons} for rows with any of these reasons in this exact order: 'missing_receipt' if amount>=25 and receipt absent/null/blank; 'large_expense' if amount>=1000; 'invalid_date' if nonempty date malformed. Output rows in input order, omit unflagged.
D8 split_allocations = {valid_rows,invalid_indexes,by_category}; consider only rows with nonempty dict allocations mapping nonempty category strings to finite numeric signed amounts. A considered row is valid iff exact sum allocations == exact row amount. valid_rows is count; invalid_indexes input order; by_category is signed rounded aggregate across allocations on valid rows only, sorted. Absent/null/empty dict allocations ignored. Allocation keys are used verbatim (fixture restricts them to canonical nonblank category names).

Acceptance cases include empty rows, missing fields, nulls, blank strings, refunds, zero, Decimal half-cent ties and round-after-summing, different currencies, duplicate IDs, forward refund links, cross-month/year/leap dates, malformed/noncanonical dates, equal ranking/streak ties, unsorted rows, generators, zero budgets and over-budget categories, unmatched refunds, and invalid split totals.
