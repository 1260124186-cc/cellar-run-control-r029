package service

import (
	"sort"
	"time"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/policyz"
)

func (s *Service) CreateFormula(operatorID string, input CreateFormulaInput) (domain.Formula, error) {
	if err := s.Authorize(operatorID, policyz.PermFormulaPlan, "POST /v1/formulas"); err != nil {
		return domain.Formula{}, err
	}
	now := s.clock.Now()
	formula := domain.Formula{
		Name:                  input.Name,
		Style:                 input.Style,
		TargetOriginalGravity: input.TargetOriginalGravity,
		TargetFinalGravity:    input.TargetFinalGravity,
		MaxFermentationTempC:  input.MaxFermentationTempC,
		MinimumDays:           input.MinimumDays,
		MaximumDays:           input.MaximumDays,
		Steps:                 []domain.FormulaStep{},
		State:                 domain.FormulaDraft,
		Version:               1,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	formula.Normalize()
	if err := formula.Validate(); err != nil {
		return domain.Formula{}, err
	}
	id, err := generateEntityID("formula")
	if err != nil {
		return domain.Formula{}, domain.NewError(domain.CodeStorage, err.Error())
	}
	formula.ID = id
	nameKey := domain.NameKey(formula.Name)

	err = s.store.Execute(func(snapshot *domain.Snapshot) error {
		if _, exists := snapshot.NameIndex[nameKey]; exists {
			return domain.NewError(domain.CodeFormulaNameConflict,
				"a formula with the same normalized name already exists")
		}
		snapshot.Formulas[formula.ID] = formula
		snapshot.NameIndex[nameKey] = formula.ID
		return nil
	})
	if err != nil {
		return domain.Formula{}, err
	}
	return formula.Clone(), nil
}

func (s *Service) SetFormulaSteps(
	operatorID string,
	id string,
	input SetFormulaStepsInput,
) (domain.Formula, error) {
	if err := s.Authorize(operatorID, policyz.PermFormulaManage, "PUT /v1/formulas/{id}/steps"); err != nil {
		return domain.Formula{}, err
	}
	var updated domain.Formula
	err := s.store.Execute(func(snapshot *domain.Snapshot) error {
		formula, ok := snapshot.Formulas[id]
		if !ok {
			return domain.NewError(domain.CodeFormulaNotFound, "formula was not found")
		}
		if err := s.checkExpected(formula.Version, input.ExpectedVersion); err != nil {
			return err
		}
		if err := formula.SetSteps(input.Steps); err != nil {
			return err
		}
		formula.UpdatedAt = s.clock.Now()
		snapshot.Formulas[id] = formula
		updated = formula.Clone()
		return nil
	})
	if err != nil {
		return domain.Formula{}, err
	}
	return updated, nil
}

func (s *Service) ApproveFormula(operatorID, id string, input VersionInput) (domain.Formula, error) {
	if err := s.Authorize(operatorID, policyz.PermFormulaManage, "POST /v1/formulas/{id}/approve"); err != nil {
		return domain.Formula{}, err
	}
	var updated domain.Formula
	err := s.store.Execute(func(snapshot *domain.Snapshot) error {
		formula, ok := snapshot.Formulas[id]
		if !ok {
			return domain.NewError(domain.CodeFormulaNotFound, "formula was not found")
		}
		if err := s.checkExpected(formula.Version, input.ExpectedVersion); err != nil {
			return err
		}
		if err := formula.Approve(s.clock.Now()); err != nil {
			return err
		}
		snapshot.Formulas[id] = formula
		updated = formula.Clone()
		return nil
	})
	if err != nil {
		return domain.Formula{}, err
	}
	return updated, nil
}

func (s *Service) RetireFormula(operatorID, id string, input VersionInput) (domain.Formula, error) {
	if err := s.Authorize(operatorID, policyz.PermFormulaManage, "POST /v1/formulas/{id}/retire"); err != nil {
		return domain.Formula{}, err
	}
	var updated domain.Formula
	err := s.store.Execute(func(snapshot *domain.Snapshot) error {
		formula, ok := snapshot.Formulas[id]
		if !ok {
			return domain.NewError(domain.CodeFormulaNotFound, "formula was not found")
		}
		if err := s.checkExpected(formula.Version, input.ExpectedVersion); err != nil {
			return err
		}
		for _, run := range snapshot.Runs {
			if run.FormulaID == id && run.State != domain.RunCompleted &&
				run.State != domain.RunAborted {
				return domain.NewError(domain.CodeFormulaInUse,
					"formula is attached to a run that is still open")
			}
		}
		if err := formula.Retire(s.clock.Now()); err != nil {
			return err
		}
		snapshot.Formulas[id] = formula
		updated = formula.Clone()
		return nil
	})
	if err != nil {
		return domain.Formula{}, err
	}
	return updated, nil
}

func (s *Service) GetFormula(operatorID, id string) (domain.Formula, error) {
	if err := s.Authorize(operatorID, policyz.PermFormulaRead, "GET /v1/formulas/{id}"); err != nil {
		return domain.Formula{}, err
	}
	var found domain.Formula
	err := s.store.View(func(snapshot domain.Snapshot) error {
		formula, ok := snapshot.Formulas[id]
		if !ok {
			return domain.NewError(domain.CodeFormulaNotFound, "formula was not found")
		}
		found = formula.Clone()
		return nil
	})
	if err != nil {
		return domain.Formula{}, err
	}
	return found, nil
}

func (s *Service) ListFormulas(operatorID string) ([]domain.Formula, error) {
	if err := s.Authorize(operatorID, policyz.PermFormulaRead, "GET /v1/formulas"); err != nil {
		return nil, err
	}
	var formulas []domain.Formula
	err := s.store.View(func(snapshot domain.Snapshot) error {
		formulas = make([]domain.Formula, 0, len(snapshot.Formulas))
		for _, formula := range snapshot.Formulas {
			formulas = append(formulas, formula.Clone())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(formulas, func(i, j int) bool {
		if formulas[i].Name == formulas[j].Name {
			return formulas[i].ID < formulas[j].ID
		}
		return formulas[i].Name < formulas[j].Name
	})
	return formulas, nil
}

func timestampPointer(value time.Time) *time.Time {
	copy := value.UTC()
	return &copy
}
