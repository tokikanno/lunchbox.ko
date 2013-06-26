// from http://stackoverflow.com/questions/7395946/knockout-js-json-has-numeric-but-knockout-changes-it-to-string-any-suggestions
(function () {
    ko.numericObservable = function(initialValue) {
        var _actual = ko.observable(initialValue);

        var result = ko.dependentObservable({
            read: function() {
                return _actual();
            },
            write: function(newValue) {
                var parsedValue = parseFloat(newValue);
                _actual(isNaN(parsedValue) ? newValue : parsedValue);
            }
        });

        return result;
    };
})();