//! Statistics for the evaluation: exact binomial intervals.
//!
//! Rates are always reported with a Clopper-Pearson 95 % upper bound, because
//! "0 successes in n trials" says almost nothing for small n (n = 40 gives a
//! 7.2 % bound). The implementation is unit-tested against the closed form.

#![forbid(unsafe_code)]

/// Exact Clopper-Pearson upper bound for `k` successes in `n` trials at α = 0.05.
#[must_use]
pub fn cp_upper(k: u64, n: u64) -> f64 {
    if n == 0 || k >= n {
        return 1.0;
    }
    if k == 0 {
        return 1.0 - 0.05f64.powf(1.0 / n as f64);
    }
    let cdf = |p: f64| -> f64 {
        let mut term = (1.0 - p).powi(n as i32);
        let mut sum = term;
        for i in 0..k {
            let i = i as f64;
            term *= (n as f64 - i) / (i + 1.0) * (p / (1.0 - p));
            sum += term;
        }
        sum
    };
    let (mut lo, mut hi) = (0.0f64, 1.0f64);
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if cdf(mid) > 0.05 {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi
}

/// Point estimate plus exact upper bound, formatted for tables.
#[must_use]
pub fn rate_s(k: u64, n: u64) -> String {
    if n == 0 {
        return "n/a".to_owned();
    }
    format!(
        "{k}/{n} = {:.1}% (95% ub {:.1}%)",
        100.0 * k as f64 / n as f64,
        100.0 * cp_upper(k, n)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_success_bounds_match_closed_form() {
        for n in [10u64, 40, 60, 100, 150, 200] {
            let expected = 1.0 - 0.05f64.powf(1.0 / n as f64);
            assert!((cp_upper(0, n) - expected).abs() < 1e-9, "n={n}");
        }
        // The sample-size table in the research track: 3/n approximation.
        assert!((cp_upper(0, 40) - 0.0721).abs() < 0.001);
        assert!((cp_upper(0, 150) - 0.0198).abs() < 0.001);
    }

    #[test]
    fn boundaries_and_monotonicity() {
        assert!((cp_upper(5, 5) - 1.0).abs() < 1e-12);
        assert!((cp_upper(0, 0) - 1.0).abs() < 1e-12);
        assert!(cp_upper(20, 40) > cp_upper(5, 40));
        assert!(cp_upper(20, 40) < cp_upper(30, 40));
        assert!(cp_upper(30, 40) > 0.5);
    }
}
